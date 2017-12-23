#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include "tcplib.h"

uint8_t g_port_list[0xFFFF] = {0}; //要扫描的端口相应的位会被置1

int threadpool_free(struct threadpool_t *pool);

int getrandom(int begin, int end) {
    struct timespec start;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start);    /* mark start time */
    return (begin + start.tv_nsec % (end - begin + 1));
}
int valid_ip_addr(char *ipAddress) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}
void help(char *app) {
    printf("Usage:   %s TCP/SYN StartIP [EndIP] Ports [/T(N)] [/t(sec)] [/(H)Banner] [/Save]\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 /T512\n", app);
    printf("Example: %s TCP 12.12.12.12/24 80 /T512\n", app);
    printf("Example: %s TCP 12.12.12.12/24 80 /T512 /t5 /Save\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 80 /T512 /HBanner\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 21 /T512 /Banner\n", app);

    printf("Example: %s TCP 12.12.12.12 1-65535 /T512\n", app);
    printf("Example: %s TCP 12.12.12.12 12.12.12.254 21,3389,5631 /T512\n", app);
    printf("Example: %s TCP 12.12.12.12 21,3389,5631 /T512\n", app);
    printf("Example: %s SYN 12.12.12.12 12.12.12.254 80\n", app);
    printf("Example: %s SYN 12.12.12.12 1-65535\n", app);
    printf("Example: %s SYN 12.12.12.12 12.12.12.254 21,80,3389\n", app);
    printf("Example: %s SYN 12.12.12.12 21,80,3389\n", app);
}

void print_buffer(unsigned char *buffer, int len) {
    int i = 0;
    int offset = 0;
    int row = 0;

    while (i < len) {
        if (i == 0) {
            printf("0x00000000:");
        }
        printf("%02X", *(buffer + i));
        if (i % 2 == 1) {
            printf(" ");
        }
        offset = i % 0x10;
        row = (int) (i / 0x10 + 1);
        if (offset == 15) {
            printf("\n0x%08X:", row * 16);
        }
        i++;
    }
    printf("\n");
    fflush(stdout);
}

void socket_timeoutset(int sockfd,int seconds,int socktype) {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, socktype==1?SO_SNDTIMEO:SO_RCVTIMEO, (char *) &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed\n");
        exit(-1);
    }
}

void uint32_to_ipstr(uint32_t ip, char *ip_ptr) { //使用网络字节序列
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    sprintf(ip_ptr, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
//    printf("%s\n", ip_ptr);
}

uint16_t checkSum(void *buffer, int size) {
    uint32_t cksum = 0;
    while (size > 1) {
        cksum += *(uint16_t *) buffer;
        size -= sizeof(uint16_t);
        buffer = (char *) buffer + sizeof(uint16_t);
    }
    if (size) cksum += *(uint16_t *) buffer;
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (uint16_t) (~cksum);
}

/*
* 得到本地要绑定的 ip
*/
uint32_t get_local_ip(char *dstIpAddr) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    int dns_port = 53;
    int err;
    struct sockaddr_in serv;
    struct sockaddr_in local;
    socklen_t locallen = sizeof(local);
    memset(&serv, 0, sizeof(serv));
    memset(&local, 0, sizeof(local));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr(dstIpAddr);//inet_addr(HostName);
    serv.sin_port = htons(dns_port);
    err = connect(sock, (const struct sockaddr *) &serv, sizeof(serv));
    err = getsockname(sock, (struct sockaddr *) &local, &locallen);
    if (-1 == err) { //failed
        exit(EXIT_FAILURE);
    }
    close(sock);
    return local.sin_addr.s_addr;
}

uint32_t hostname_to_ip(char *hostname) {
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ((he = gethostbyname(hostname)) == NULL) {
        herror("gethostbyname");
        return 1;
    } else {
        addr_list = (struct in_addr **) he->h_addr_list;
        for (i = 0; addr_list[i] != NULL; i++) {
            return addr_list[i]->s_addr;
        }
    }
}

void parse_port_str(char *poststr, PortRange *port_range) {
    int idx, count = 0;
    char *temp = strtok(poststr, ",");
    while (temp) {
//        printf("%s \n",temp);
        uint16_t start, end;
        char *slash = NULL;
        char port[64] = {0};
        if ((slash = strchr(temp, '-'))) { //23-1000

            strncpy(port, temp, strlen(temp) - strlen(slash)); //1-65535 ==> 1
            start = atoi(port);
            end = atoi(slash + 1);

            if (end < start) {
                continue;
            }
            for (idx = start; idx <= end; idx++) {
                g_port_list[idx] = 1;
                count++;
            }
        } else {
            start = atoi(temp);
            g_port_list[start] = 1;
            count++;
        }
        temp = strtok(NULL, ",");
    }
    port_range->g_portlist = g_port_list;
    port_range->count = count;
}

void parse_ip_str(char *startIpAddr, char *endIpAddr, IpRange *ipinfo) {
    char startIpStr[256];
    char *slash = NULL;
    unsigned int range = 0;
    unsigned int submask = 0;
    memset(startIpStr, 0, sizeof(startIpStr));

    if (endIpAddr!=NULL) {
        ipinfo->start_addr = inet_addr(startIpAddr);
        ipinfo->end_addr = inet_addr(endIpAddr);
    }else{
        slash = strchr(startIpAddr, '/'); //get "/24"
        if (slash) {
            strncpy(startIpStr, startIpAddr, strlen(startIpAddr) - strlen(slash)); //192.168.0.0/24 ==> 192.168.0.0
            int bit = atoi(slash + 1); //24
            range = 0xFFFFFFFF >> bit;
            submask = 0xFFFFFFFF << (32 - bit);

            ipinfo->start_addr = (inet_addr(startIpStr) & ntohl(submask)) + ntohl(1);    //保存4字节IP主机字节序
            ipinfo->end_addr = (inet_addr(startIpStr) & ntohl(submask)) + ntohl(range - 1);//保存4字节IP主机字节序
        } else {
            // 起始IP参数转化(支持域名)
            uint32_t ipaddr = hostname_to_ip(startIpAddr);
            ipinfo->start_addr = ipaddr;//保存4字节IP主机字节序
            ipinfo->end_addr = ipaddr;  //保存4字节IP主机字节序
        }
    }

}

/**
 * 线程池
 */

#define MAX_THREADS 512
#define MAX_QUEUE 65536

typedef enum {
    threadpool_invalid = -1,
    threadpool_lock_failure = -2,
    threadpool_queue_full = -3,
    threadpool_shutdown = -4,
    threadpool_thread_failure = -5
} threadpool_error_t;

typedef enum {
    threadpool_graceful = 1
} threadpool_destroy_flags_t;

typedef enum {
    immediate_shutdown = 1,
    graceful_shutdown = 2
} threadpool_shutdown_t;


static void *threadpool_thread(void *threadpool) {
    struct threadpool_t *pool = (struct threadpool_t *) threadpool;
    ThreadTask task;

    for (;;) {
        /* Lock must be taken to wait on conditional variable */
        pthread_mutex_lock(&(pool->lock));

        /* Wait on condition variable, check for spurious wakeups.
           When returning from pthread_cond_wait(), we own the lock. */
        while ((pool->count == 0) && (!pool->shutdown)) {
            pthread_cond_wait(&(pool->notify), &(pool->lock));
        }

        if ((pool->shutdown == immediate_shutdown) ||
            ((pool->shutdown == graceful_shutdown) &&
             (pool->count == 0))) {
            break;
        }

        /* Grab our task */
        task.function = pool->queue[pool->head].function;
        task.argument = pool->queue[pool->head].argument;
        pool->head += 1;
        pool->head = (pool->head == pool->queue_size) ? 0 : pool->head;
        pool->count -= 1;

        /* Unlock */
        pthread_mutex_unlock(&(pool->lock));

        /* Get to work */
        (*(task.function))(task.argument);
    }

    pool->started--;
    pthread_mutex_unlock(&(pool->lock));
    pthread_exit(NULL);
}
ThreadPool *threadpool_create(int thread_count, int queue_size, int flags) {
    if (thread_count <= 0 || thread_count > MAX_THREADS || queue_size <= 0 || queue_size > MAX_QUEUE) {
        return NULL;
    }

    struct threadpool_t *pool;
    int i;

    if ((pool = (ThreadPool *) malloc(sizeof(ThreadPool))) == NULL) {
        goto err;
    }

    /* Initialize */
    pool->thread_count = 0;
    pool->queue_size = queue_size;
    pool->head = pool->tail = pool->count = 0;
    pool->shutdown = pool->started = 0;

    /* Allocate thread and task queue */
    pool->threads = (pthread_t *) malloc(sizeof(pthread_t) * thread_count);
    pool->queue = (ThreadTask *) malloc
            (sizeof(ThreadTask) * queue_size);

    /* Initialize mutex and conditional variable first */
    if ((pthread_mutex_init(&(pool->lock), NULL) != 0) ||
        (pthread_cond_init(&(pool->notify), NULL) != 0) ||
        (pool->threads == NULL) ||
        (pool->queue == NULL)) {
        goto err;
    }

    /* Start worker threads */
    for (i = 0; i < thread_count; i++) {
        if (pthread_create(&(pool->threads[i]), NULL, threadpool_thread, (void *) pool) != 0) {
            threadpool_destroy(pool, 0);
            return NULL;
        }
        pool->thread_count++;
        pool->started++;
    }

    return pool;

    err:
    if (pool) {
        threadpool_free(pool);
    }
    return NULL;
}

int threadpool_add(struct threadpool_t *pool, void (*function)(void *), void *argument, int flags) {
    int err = 0;
    int next;

    if (pool == NULL || function == NULL) {
        return threadpool_invalid;
    }

    if (pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }

    next = pool->tail + 1;
    next = (next == pool->queue_size) ? 0 : next;

    do {
        /* Are we full ? */
        if (pool->count == pool->queue_size) {
            err = threadpool_queue_full;
            break;
        }
        /* Are we shutting down ? */
        if (pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }
        /* Add task to queue */
        pool->queue[pool->tail].function = function;
        pool->queue[pool->tail].argument = argument;
        pool->tail = next;
        pool->count += 1;
        /* pthread_cond_broadcast */
        if (pthread_cond_signal(&(pool->notify)) != 0) {
            err = threadpool_lock_failure;
            break;
        }
    } while (0);

    if (pthread_mutex_unlock(&pool->lock) != 0) {
        err = threadpool_lock_failure;
    }

    return err;
}
int threadpool_free(struct threadpool_t *pool) {
    if (pool == NULL || pool->started > 0) {
        return -1;
    }
    /* Did we manage to allocate ? */
    if (pool->threads) {
        free(pool->threads);
        free(pool->queue);

        /* Because we allocate pool->threads after initializing the
           mutex and condition variable, we're sure they're
           initialized. Let's lock the mutex just in case. */
        pthread_mutex_lock(&(pool->lock));
        pthread_mutex_destroy(&(pool->lock));
        pthread_cond_destroy(&(pool->notify));
    }
    free(pool);
    return 0;
}
int threadpool_destroy(struct threadpool_t *pool, int flags) {
    int i, err = 0;

    if (pool == NULL) {
        return threadpool_invalid;
    }

    if (pthread_mutex_lock(&(pool->lock)) != 0) {
        return threadpool_lock_failure;
    }

    do {
        /* Already shutting down */
        if (pool->shutdown) {
            err = threadpool_shutdown;
            break;
        }

        pool->shutdown = (flags & threadpool_graceful) ? graceful_shutdown : immediate_shutdown;

        /* Wake up all worker threads */
        if ((pthread_cond_broadcast(&(pool->notify)) != 0) ||
            (pthread_mutex_unlock(&(pool->lock)) != 0)) {
            err = threadpool_lock_failure;
            break;
        }

        /* Join all worker thread */
        for (i = 0; i < pool->thread_count; i++) {
            if (pthread_join(pool->threads[i], NULL) != 0) {
                err = threadpool_thread_failure;
            }
        }
    } while (0);

    /* Only if everything went well do we deallocate the pool */
    if (!err) {
        threadpool_free(pool);
    }
    return err;
}