#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <execinfo.h>
#include <fcntl.h>

/*
    @desc 
    We can't use jiffies directly in user mode.
    
*/
/* -------------------------- network logger section start ------------------------------------*/

static struct sockaddr_in server_addr, client_addr;
static char pidstr[20];
static int log_sock_fd, log_length;
static int is_log_udpsocket_init;
static int is_log_tcpsocket_init;
static pid_t current_pid;

#define TARGET_PC_IP "192.168.0.204"

static unsigned long debug_counter;

static void init_udp_socket()
{
    log_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    bzero(&client_addr, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = INADDR_ANY;
    client_addr.sin_port = 0;
    
    bind(log_sock_fd, (struct sockaddr*)&client_addr, sizeof(client_addr));
    
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_aton(TARGET_PC_IP, &server_addr.sin_addr.s_addr);
    server_addr.sin_port = htons(9876);
    current_pid = getpid();
    sprintf(pidstr,"%d:", (unsigned int)current_pid);
}

static void init_tcp_socket()
{
    log_sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ( log_sock_fd < 0 )
  	{
  	    printf("........................... to create socket failed. ............................\n");
  	}
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    inet_aton(TARGET_PC_IP, &server_addr.sin_addr.s_addr);
    server_addr.sin_port = htons(9876);
    if ( connect(log_sock_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 )
  	{
  	    printf("........................... to connect socket failed. (%s) (%d)............................\n", TARGET_PC_IP, 9876);
  	}
    
    current_pid = getpid();
    sprintf(pidstr,"%d:", (unsigned int)current_pid);
}

static void send_log_by_udp(const char* buffer)
{
    char sendline[1024] = {0,};
    if ( is_log_udpsocket_init == 0 )
    {
        is_log_udpsocket_init = 1;
        init_udp_socket();
    }
    snprintf(sendline, 1024, "%s:%d:%s", pidstr, ++debug_counter, buffer);
    sendto(log_sock_fd, sendline, strlen(sendline), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
}

static void send_log_by_tcp(const char* buffer)
{
    char sendline[1024] = {0,};
    if ( is_log_tcpsocket_init == 0 )
    {
        is_log_tcpsocket_init = 1;
        init_tcp_socket();
    }
    snprintf(sendline, 1024, "%s:%d:%s\n", pidstr, ++debug_counter, buffer);
    if ( log_sock_fd < 0 )
        printf("there is no server to listen.");
    else
        write(log_sock_fd, sendline, strlen(sendline));
}

/* -------------------------- network logger section end ------------------------------------*/

/* -------------------------- file logger section start ------------------------------------*/
#define TARGET_FILE "/mnt/sda/log_file"

static int is_init_log_file = 0;

static void init_log_file()
{
    log_sock_fd = open(TARGET_FILE, O_RDWR);
    current_pid = getpid();
    sprintf(pidstr,"%d:", (unsigned int)current_pid);
}

static void send_log_by_file(const char* buffer)
{
    char sendline[1024] = {0,};
    snprintf(sendline, 1024, "%s:%d:%s\n", pidstr, ++debug_counter, buffer);
    if ( is_init_log_file == 0 )
    {
        is_init_log_file = 1;
        init_log_file();
    }
    if ( log_sock_fd >= 0 )
        write(log_sock_fd, sendline, 1024);
    else
        puts(".................... There is no target file.. .............................");
}
/* -------------------------- file logger section end ------------------------------------*/

/*
    @desc 
    We can't use jiffies directly in user mode.
    
*/
//extern unsigned long volatile jiffies;

static void* (*org_malloc)(size_t);
static void (*org_free)(void*);
static void* (*org_calloc)(size_t, size_t);
static void* (*org_realloc)(void*, size_t);
static void* (*org_memalign)(size_t alignment, size_t size);

void* malloc (size_t size);
void free (void* ptr);
void* calloc (size_t num, size_t size);
void* realloc (void* ptr, size_t size);
void* memalign(size_t alignment, size_t size);

extern void exit(int status);

#define LOG_DEBUG 1
#define LOG_INFO 2
#define LOG_ERROR 3

#define DEFAULT_LOG_TYPE LOG_INFO
#define MALLOC_DEBUG_TAG "__--MALLOC_DEBUG--__"
#define STRACE_DEBUG_TAG "__--STRACE_DEBUG--__"

static pthread_mutex_t print_log_buffer_lock = PTHREAD_MUTEX_INITIALIZER;
static char debug_inner_buffer[1000];

#define CONSOLE_LOG_ENABLE 0
#define UDP_LOG_ENABLE 0
#define FILE_LOG_ENABLE 0

inline void DEBUG_PUTS(int x, const char* y) {
#if CONSOLE_ENABLE
    { 
    if ( (x) >= DEFAULT_LOG_TYPE )
        puts(y);
    }
#endif
#if UDP_LOG_ENABLE
    {
    if( (x) >= DEFAULT_LOG_TYPE )
        send_log_by_udp(y);
    }
#endif
#if TCP_LOG_ENABLE
    {
    if( (x) >= DEFAULT_LOG_TYPE )
        send_log_by_tcp(y);
    }
#endif
#if FILE_LOG_ENABLE
    {
    if( (x) >= DEFAULT_LOG_TYPE )
        send_log_by_file(y);
    }
#endif
}

#define DEBUG_PRINTF(x, ...)  { \
    if ( (x) >= DEFAULT_LOG_TYPE ) { \
        pthread_mutex_lock(&print_log_buffer_lock); \
        memset(debug_inner_buffer, 0x00, 1000); \
        sprintf(debug_inner_buffer, __VA_ARGS__); \
        DEBUG_PUTS(x, debug_inner_buffer); \
        pthread_mutex_unlock(&print_log_buffer_lock); \
    } \
}

/*
    @desc
    This preload functions need to be initialized.
    So we use shared library initialize funtion.
*/
static void init_original_handler() __attribute__((constructor));
static void uninit_original_handler() __attribute__((destructor));


/*
    @desc 
    
    When to use 'calloc' function by using LD_PRELOAD,
    it meets infinite loop because 'dlsym' function uses 'calloc' function. so it makes recursive loop.
    
    To prevent it. We suggest the temporary calloc implementation to supply inner buffers not to use original function call.
    
*/
/* -------------------------- internal buffer section start ------------------------------------*/
static unsigned char inner_buffer[4096];
static int inner_buffer_count;
static void* inner_buffer_pointers[10]; 
static int inner_buffer_pointer_size[10];

static void init_buffer()
{
    inner_buffer_count = 0;
    inner_buffer_pointers[inner_buffer_count] = inner_buffer;
}

static void* malloc_with_inner_buffer(int size)
{
    void* allocated_memory = NULL;
    DEBUG_PRINTF(LOG_DEBUG, "malloc with inner buffer. size(%d).\n", size);
    if ( inner_buffer_count >= 9 )
    {
        DEBUG_PRINTF(LOG_ERROR, "<<<< malloc failed.>>>> inner buffer count can't exceed 10..\n");
        return NULL;
    }
    if ( ( ( inner_buffer_pointers[inner_buffer_count] - (void*)inner_buffer ) + size ) >= 4096 )
    {
        DEBUG_PRINTF(LOG_ERROR, "<<<< malloc failed.>>>> inner buffer size can't exceed 4096..\n");
        return NULL;
    }
    allocated_memory = inner_buffer_pointers[inner_buffer_count];
    inner_buffer_pointer_size[inner_buffer_count] = size;
    inner_buffer_count++;
    inner_buffer_pointers[inner_buffer_count] = (void*)inner_buffer_pointers[inner_buffer_count - 1] + size;

    DEBUG_PRINTF(LOG_DEBUG, "malloc buffered pointer(%p) size(%d) next pointer(%p).\n", inner_buffer_pointers[inner_buffer_count-1], size, inner_buffer_pointers[inner_buffer_count] );

    return allocated_memory;
}

static void free_with_inner_buffer(void* ptr)
{
    int cnt = 0;
    DEBUG_PRINTF(LOG_DEBUG, "free with inner buffer. size(%p).\n", ptr);
    for(; cnt < inner_buffer_count ; cnt++)
    {
        if (inner_buffer_pointers[cnt] == ptr)
            inner_buffer_pointer_size[cnt] = 0;
    }
    for(cnt = inner_buffer_count - 1; cnt >= 0 ; cnt--)
    {
        if (inner_buffer_pointer_size[cnt] == 0)
            inner_buffer_count--;
        else
            break;
    }
}
/* -------------------------- internal buffer section end ------------------------------------*/


/* -------------------------- initialization / uninitialization section start ------------------------------------*/
static void init_original_handler()
{
    puts("======== init debug malloc object ========");
    init_buffer();
    org_malloc=dlsym(RTLD_NEXT,"malloc");
    if ( org_malloc == NULL )
    {
        puts("========[malloc] dlsym failed. ========.\n");
        exit(1);
    }
    org_free = dlsym(RTLD_NEXT,"free");
    if ( org_free == NULL )
    {
        puts("========[free] dlsym failed. ========.\n");
        exit(1);
    }
    org_calloc = dlsym(RTLD_NEXT,"calloc");
    if ( org_calloc == NULL )
    {
        puts("========[calloc] dlsym failed. ========");
        exit(1);
    }
    org_realloc = dlsym(RTLD_NEXT,"realloc");
    if ( org_realloc == NULL )
    {
        puts("========[realloc] dlsym failed. ========.\n");
        exit(1);
    }
    org_memalign = dlsym(RTLD_NEXT,"memalign");
    if ( org_memalign == NULL )
  	{
        puts("========[memalign] dlsym failed. ========.\n");
        exit(1);
  	}
}

static void uninit_original_handler()
{
    puts("======== uninit debug malloc object =========.\n");
}

#define wait_to_finish_init(x)	\
{	\
    while(x == NULL) init_original_handler();	\
}

/* -------------------------- initialization / uninitialization section end ------------------------------------*/

/*
    @desc
    We need to implement binary tree index. to search pointer in the big cache tables.
*/
/* -------------------------- index node section start ------------------------------------*/
#define CACHE_ENABLE 0 


#define MALLOC_POINTER_CACHED_MAX 30
#define CACHE_PAGE_MAX 200
#define LOG_BUFFER_LINE_LETTER_MAX 80  // CHARACTERS
#define LOG_BUFFER_MAX_LINE_PER_FUNC 1

typedef struct _TREE_NODE_ {
    struct _TREE_NODE_ *_prev;
    void* allocated;
    int page;
    int position;
    struct _TREE_NODE_ *_next;
} TREE_NODE_T;

static pthread_mutex_t index_lock = PTHREAD_MUTEX_INITIALIZER;

static TREE_NODE_T index_tree[CACHE_PAGE_MAX * MALLOC_POINTER_CACHED_MAX + 1];
static int usable_position = 0;
static int root_position = -1;    // root_position may be midium value of list.
static int node_size = 0;

typedef enum _MALLOC_FUNC_TYPE_ {
    MALLOC = 0,
    FREE,
    CALLOC,
    REALLOC_FREE,
    REALLOC_ALLOC,
    MEMALIGN,
} MALLOC_FUNC_TYPE_T;

#define MALLOC_METHOD "MALLOC"
#define FREE_METHOD "FREE"
#define CALLOC_METHOD "CALLOC"
#define REALLOC_FREE_METHOD "REALLOC_FREE"
#define REALLOC_ALLOC_METHOD "REALLOC_ALLOC"
#define MEMALIGN_METHOD "MEMALIGN"

typedef struct _MALLOC_INFO_ {
    void* allocated;
    MALLOC_FUNC_TYPE_T t_function;
    unsigned long count;
    int length;
    int size;
    int is_deleted;         // After to display it, this value changed from 0 to 1.
#if CACHE_ENABLE
    TREE_NODE_T* index;
#endif
} MALLOC_INFO_T;

static MALLOC_INFO_T allocated_memory_array_ex[CACHE_PAGE_MAX][MALLOC_POINTER_CACHED_MAX];
static int allocated_memory_array_page = 0;

#define allocated_memory_array allocated_memory_array_ex[allocated_memory_array_page]

// Implement sorted List.
#if CACHE_ENABLE
static void inline make_parent_child_relation(TREE_NODE_T* parent, TREE_NODE_T* child)
{
    if ( parent )
        parent->_next = child;
    if ( child )
        child->_prev = parent;
}

static void inline check_index_link()
{
    int node_count_check = 0;
    TREE_NODE_T* curNode = &index_tree[root_position];
    do
    {
        node_count_check++;
        if ( ( curNode == &index_tree[root_position] ) && ( curNode->_prev != NULL ) )
            DEBUG_PRINTF(LOG_ERROR, "index_node[%d] is Root. But It has ._prev value= %p.", curNode->position, curNode->_prev);
        if ( curNode->allocated == NULL )
            DEBUG_PRINTF(LOG_ERROR, "index_node[%d] is a normal node. But It has NULL value= %p.", curNode->position);
    }
    while( curNode = curNode->_next );
    
    if ( node_count_check != node_size )
  	{
  	    DEBUG_PRINTF(LOG_ERROR, "index_tree Size is %d. But Size by counting list is %d.", node_size, node_count_check);
  	    node_size = node_count_check;
  	}
    
}

static void inline print_full_index_info()
{
    DEBUG_PRINTF(LOG_DEBUG, "usable_position = %d.root_position = %d.node_size = %d.", usable_position, root_position, node_size);
    check_index_link();
#if 0
    TREE_NODE_T* curNode = &index_tree[root_position];
    TREE_NODE_T* prevNode = NULL;
    do {
        DEBUG_PRINTF(LOG_INFO, "index_tree ._prev(%p).cur(%p) _next(%p)..allocated(%p).page(%d).pos(%d)",  curNode->_prev, curNode, curNode->_next, curNode->allocated, curNode->page, curNode->position);
        if ( prevNode && ( prevNode->_next != curNode || curNode->_prev != prevNode ) )
            DEBUG_PRINTF(LOG_ERROR, "[ERR]index_tree[%p][%d] has error. Mismatch PREV/CURR pointer.(prev->_next)(%p)(curNode)(%p) (curNode->_prev)(%p)(prev)(%p)", curNode, curNode->position, prevNode->_next, curNode, curNode->_prev, prevNode);
        prevNode = curNode;
    } while( curNode = curNode->_next );
#endif
}

static inline void find_empty_room_index_tree()
{
    static long cnt = 0;
    cnt++;
    cnt %= 10;
    if ( cnt == 0 )
    {
        int index_cnt;
        for ( index_cnt = 0 ; index_cnt < CACHE_PAGE_MAX * MALLOC_POINTER_CACHED_MAX ; index_cnt++ )
        {
            if ( index_tree[index_cnt].allocated == NULL )
            {
                usable_position = index_cnt;
                break;
            }
        }
    }
    else
  	{
	    while (index_tree[usable_position].allocated != NULL) { DEBUG_PRINTF(LOG_DEBUG, "INDEX_NODE[%d].allocated(%p) in find_empty.",usable_position,index_tree[usable_position].allocated );usable_position++;}
	    if ( usable_position >= ( sizeof(index_tree) / sizeof(TREE_NODE_T) ) )
	        DEBUG_PRINTF(LOG_ERROR, "[ERROR] This is not valid position(%d) in index tree. It couldn't be larger than %d.", usable_position, sizeof(index_tree) / sizeof(TREE_NODE_T));
  	}
 	  //print_full_index_info();
}

static TREE_NODE_T* find_index_node(void* allocated)
{
    if ( root_position == -1 )
        return NULL;
    TREE_NODE_T* curNode = &index_tree[root_position];
    do {
    	if ( curNode->allocated == allocated )
    		break;
    } while( curNode = curNode->_next );
    return curNode;
}

static TREE_NODE_T* insert_node(void* allocated, int page)
{
    DEBUG_PRINTF(LOG_DEBUG, "insert_node start....(%p)(%d)",allocated, page );
	  print_full_index_info();
    pthread_mutex_lock(&index_lock);
    int exist_same_value = 0;
	  TREE_NODE_T* newNode = &index_tree[usable_position];
    newNode->_prev = NULL;
    newNode->allocated = allocated;
    newNode->page = page;
    newNode->position = usable_position;
    newNode->_next = NULL;
    node_size++;
    if ( root_position == -1 )
    {
        root_position = 0;
    }
    else
    {
        TREE_NODE_T* curNode = &index_tree[root_position];
        TREE_NODE_T* lastNode = NULL;
        do {
            if ( curNode->allocated > newNode->allocated )
            {
                if ( curNode->position == root_position )
                    root_position = newNode->position;
                make_parent_child_relation(curNode->_prev, newNode);
                make_parent_child_relation(newNode, curNode);
                make_parent_child_relation(curNode, NULL);
                break;
            }
            else if ( curNode->allocated == newNode->allocated )
          	{
          	    memset(newNode, 0x00, sizeof(TREE_NODE_T));
          	    exist_same_value = 1;
          	    break;
          	}
            lastNode = curNode;
        } while ( curNode = curNode->_next );
        if ( exist_same_value )
      	{
      	    newNode = NULL;
      	}
        else if ( curNode == NULL )
        {
            make_parent_child_relation(lastNode, newNode);
        }
	      print_full_index_info();
    }
    DEBUG_PUTS(LOG_DEBUG, "After to insert calc end....");
    // calculate next usable postion in index array.
    find_empty_room_index_tree();
    pthread_mutex_unlock(&index_lock);
    DEBUG_PUTS(LOG_DEBUG, "insert_node end....");
    return newNode;
}

static void delete_node_from_tree(TREE_NODE_T* node)
{
    DEBUG_PRINTF(LOG_DEBUG, "delete_node_from_tree start......prev(%p) - (%p)(%d) - next(%p)", node->_prev, node, node->position, node->_next);
    TREE_NODE_T* prevNode = node->_prev;
    TREE_NODE_T* nextNode = node->_next;
    
    // There are four case.
    if ( prevNode == NULL && nextNode == NULL )
    {
        // Clear Index Tree. All Clear.
        root_position = -1;
        usable_position = 0;
        node_size--;
        if ( node_size != 0 )
            DEBUG_PRINTF(LOG_ERROR, "[ERROR] invalid case. It can't happen. After to truncate last index node. but node size insn't zero.");
    }
    else
  	{
        if ( (prevNode == NULL) && (nextNode != NULL) ) 
      	{
      	    if ( node != &index_tree[root_position]  )
    	    	{
                DEBUG_PRINTF(LOG_ERROR, "[ERROR invalid case. It's not root node. but It doesn't have parent Node. (%p)(%d)-next(%p)(%d).", node, node->position, node->_next, (node->_next) ? node->_next->position : -1);
    	    	}
            else
          	{
                root_position = node->_next->position;
          	}
      	}
  	    int cur_position = node->position;
        make_parent_child_relation(prevNode, nextNode);
        memset(node, 0x00, sizeof(TREE_NODE_T));
        if ( usable_position > cur_position )
            usable_position = cur_position;
        node_size--;
  	}
    memset(node, 0x00, sizeof(TREE_NODE_T));
    DEBUG_PRINTF(LOG_DEBUG, "delete_node_from_tree end....(%p)(%d).", node, node->position);
}

static int delete_node(void* allocated)
{
    int page = 0;
    DEBUG_PRINTF(LOG_DEBUG, "delete_node start.....allocated (%p).", allocated);
    pthread_mutex_lock(&index_lock);
#if 0
/*
    int cur_position = root_position;
    print_full_index_info();
    if ( cur_position >= 0 )
    {
        int move_count = node_size;
        if ( index_tree[cur_position].allocated > allocated )
            page = -1;
        else
      	{
            while(index_tree[cur_position].allocated != allocated)
            {
                move_count = (move_count == 1) ? 0 : (move_count / 2 + ( 0x1 & move_count ));
                //move_count = move_count / 2 + ( 0x1 & move_count );  // If the move value is odd, we add 1 into it.
                int move_count_temp = move_count;
                int is_accend = ( index_tree[cur_position].allocated < allocated ) ? 1 : 0;
                DEBUG_PRINTF("move_count : %d, cur_position : %d, allocated :%p, is_accend : %d.\n", move_count, cur_position, allocated, is_accend);
                if ( move_count == 0 )
                {
                    DEBUG_PRINTF("%s DO NOT FOUND POINTER(%p).\n", MALLOC_DEBUG_TAG, allocated);
                    page = -1;
                    break;
                }
                while( move_count_temp-- > 0 ) {
                    if ( is_accend )
                  	{
                        if ( index_tree[cur_position]._next )
                            cur_position = index_tree[cur_position]._next->position;
                  	}
                    else
                    {
                        if ( index_tree[cur_position]._prev )
                    	      cur_position = index_tree[cur_position]._prev->position;
                    }
                    	  
                }
            }
        }
        if ( page != -1 )
      	{
      	    page = index_tree[cur_position].page;
      	    delete_node_from_tree(&index_tree[cur_position]);
      	}
    }
    else
        page = -1;
*/
#else
    TREE_NODE_T* matched_node = find_index_node(allocated);
    if ( matched_node == NULL ) {
        page = -1;
    }
    else
    {
        page = matched_node->page;
        delete_node_from_tree(matched_node);
    }
#endif
    print_full_index_info();
    DEBUG_PRINTF(LOG_DEBUG, "delete_node end.....allocated (%p) matched index(%p)(%d).", allocated, matched_node, (matched_node) ? matched_node->position : -1 );
    pthread_mutex_unlock(&index_lock);
    return page;
}

static void delete_index_node_by_page()
{
    int cnt;
    DEBUG_PUTS(LOG_DEBUG, "delete_index_node_by_page start.....");
    pthread_mutex_lock(&index_lock);
    if ( root_position == -1 )
        return;
    TREE_NODE_T* curNode = &index_tree[root_position];
    do
    {
        if (curNode->page == allocated_memory_array_page)
            delete_node_from_tree(curNode);
    }
    while( curNode = curNode->_next );
    pthread_mutex_unlock(&index_lock);
    DEBUG_PUTS(LOG_DEBUG, "delete_index_node_by_page end.....");
}

#endif

/*
#define BACK_INDEX_RESOLUTION 0x1fffff
#define BACK_INDEX_MAX_COUNT 100
#define POINTER_TO_INDEX(x) ((unsigned int)((unsigned int)x >> 21))
static int back_heap_index[BACK_INDEX_RESOLUTION][BACK_INDEX_MAX_COUNT];

void back_heap_index_init()
{
    memset(back_heap_index,-1,sizeof(back_heap_index));
}

inline int* get_heap_array_position_list(void* pointer)
{
	  static int is_init = 0;
	  if ( is_init == 0 )
	  {
	      is_init = 1;
	      back_heap_index_init();
	  }
    return back_heap_index[POINTER_TO_INDEX(pointer)];
}

inline void add_heap_index(void* pointer, int index)
{
    int cnt = 0;
    int* position_list = get_heap_array_position_list(pointer); 
    for ( ; cnt < BACK_INDEX_MAX_COUNT ; cnt++ )
    {
        if ( position_list[cnt] == -1 )
            position_list[cnt] = index;
    }
    if ( cnt >= BACK_INDEX_MAX_COUNT )
        DEBUG_PRINTF(LOG_ERROR, "[CRITICAL WARNING] REBALANCE RESOLUTION SIZE IN CACHE INDEX.");
}

inline void remove_heap_index(void* pointer, int index)
{
    int cnt = 0;
    int* position_list = get_heap_array_position_list(pointer); 
    for ( ; cnt < BACK_INDEX_MAX_COUNT ; cnt++ )
    {
        if ( position_list[cnt] == index )
        {
            position_list[cnt] = -1;
        }
    }
}
*/

/* -------------------------- index node section end ------------------------------------*/

/*
    @desc
    We cant' see all the log lines from memory allocation functions.
    We need to remove duplicated pointer already removed from the memory before to print logs.
    So we need hashtable to find / sort / insert new allocated memory.

*/
/* -------------------------- allocated memory cache section start ------------------------------------*/
static pthread_mutex_t hashtable_lock = PTHREAD_MUTEX_INITIALIZER;


static void flush_log_buffer();
static void print_format_log(MALLOC_FUNC_TYPE_T func_type, int cache_index, unsigned long counter, void* ptr, int length1, int length2);

static inline int is_bigtable(MALLOC_INFO_T* item);
static void insert_big_table_info(MALLOC_INFO_T* itemToBeFlushed);
static int delete_from_big_table_info(void* allocated, int* malloc_length);

//static MALLOC_INFO_T* allocated_memory_array;

void flush_cache()
{
    DEBUG_PUTS(LOG_DEBUG, "flush_cache start.....");
    pthread_mutex_lock(&hashtable_lock);
    allocated_memory_array_page++;
    allocated_memory_array_page %= CACHE_PAGE_MAX;
#if CACHE_ENABLE
    delete_index_node_by_page();
#endif
    flush_log_buffer();
    memset(allocated_memory_array, 0x00, sizeof(allocated_memory_array));
    pthread_mutex_unlock(&hashtable_lock);
}

int insert_new_memory_allocation(MALLOC_FUNC_TYPE_T func_type, unsigned long count, void* allocated, int length, int size)
{
    int cnt;
    DEBUG_PUTS(LOG_DEBUG, "insert_new_memory_allocation start.....");
    pthread_mutex_lock(&hashtable_lock);
    for (cnt = 0 ; cnt < MALLOC_POINTER_CACHED_MAX ; cnt++ )
    {
        if ( ( allocated_memory_array[cnt].allocated == NULL ) || ( allocated_memory_array[cnt].is_deleted != 0 ) )
        {
            allocated_memory_array[cnt].t_function = func_type;
            allocated_memory_array[cnt].allocated = allocated;
            allocated_memory_array[cnt].count = count;
            allocated_memory_array[cnt].length = length;
            allocated_memory_array[cnt].size = size;
            allocated_memory_array[cnt].is_deleted = 0;
#if 0 
            add_heap_index(allocated, cnt + allocated_memory_array_page * MALLOC_POINTER_CACHED_MAX);
#endif
#if CACHE_ENABLE
            allocated_memory_array[cnt].index = insert_node(allocated, allocated_memory_array_page);
#endif
            break;
        }
    }
    if ( cnt >= MALLOC_POINTER_CACHED_MAX )
        cnt = -1;
#if CACHE_ENABLE
    else if ( allocated_memory_array[cnt].index == NULL )
    {
        cnt = -2; // There is same item on the list. so
        memset(&allocated_memory_array[cnt], 0x00, sizeof(allocated_memory_array[cnt]));
        print_format_log(func_type, -1, count, allocated, length, size );
    }
#endif
    else
  	{
  	    if ( is_bigtable( &allocated_memory_array[cnt] ) )
  	        insert_big_table_info( &allocated_memory_array[cnt] );
        print_format_log(func_type, cnt, count, allocated, length, size );
    }

    pthread_mutex_unlock(&hashtable_lock);

    return cnt;
}

void delete_memory_allocation(MALLOC_FUNC_TYPE_T func_type, unsigned long counter, void* allocated, int* length, int* size)
{
    int page_cnt;
    int cnt;
    DEBUG_PUTS(LOG_DEBUG, "delete_memory_allocation start.....");
    pthread_mutex_lock(&hashtable_lock);
#if CACHE_ENABLE
    page_cnt = delete_node(allocated);
    if ( page_cnt < 0 )
        print_format_log(func_type, -1, counter, allocated, 0, 0);
    else
  	{
        for (cnt = 0 ; cnt < MALLOC_POINTER_CACHED_MAX ; cnt++ )
        {
            if (allocated_memory_array_ex[page_cnt][cnt].allocated == allocated )
            {
                *length = allocated_memory_array_ex[page_cnt][cnt].length;
                *size = allocated_memory_array_ex[page_cnt][cnt].size;
                allocated_memory_array_ex[page_cnt][cnt].is_deleted = 1;
                break;
            }
        }
  	}
#else
#if 1
    int is_found = 0;
    int prev_length = 0;
    for (page_cnt = 0 ; ( page_cnt < CACHE_PAGE_MAX ) && ( is_found == 0 ) ; page_cnt++ )
    {
        for (cnt = 0 ; cnt < MALLOC_POINTER_CACHED_MAX && ( is_found == 0 ) ; cnt++ )
        {
            if (allocated_memory_array_ex[page_cnt][cnt].allocated == allocated )
            {
                switch( allocated_memory_array_ex[page_cnt][cnt].t_function )
                {
                    case  MALLOC :
                  	{
                        prev_length = allocated_memory_array_ex[page_cnt][cnt].length;
                  	}
                  	break;
                    case  CALLOC :
                  	{
                        prev_length = allocated_memory_array_ex[page_cnt][cnt].length * allocated_memory_array_ex[page_cnt][cnt].size;
                  	}
                  	break;
                    case  REALLOC_ALLOC :
                  	{
                        prev_length = allocated_memory_array_ex[page_cnt][cnt].length;
                  	}
                  	break;
                    case  MEMALIGN :
                  	{
                        prev_length = allocated_memory_array_ex[page_cnt][cnt].size;
                  	}
                  	break;
                    case	FREE :
                    case  REALLOC_FREE :
                  	{
                  	}
                    break;
                    default :
                    	DEBUG_PRINTF(LOG_ERROR, "%s there is invalid function type. %d.\n",MALLOC_DEBUG_TAG, func_type);
                }
                *length = prev_length;
                *size = 0;
                allocated_memory_array_ex[page_cnt][cnt].is_deleted = 1;
                is_found = 1;
            }
        }
    }
    delete_from_big_table_info(allocated, length);
    if ( is_found == 0 )
  	{
  	    // We can't find matched pointer in cache. you should print this.
  	    print_format_log(func_type, -1, counter, allocated, prev_length, 0);
  	}
#else
    int is_found = 0;
    int* position_list = get_heap_array_position_list(allocated);
    for ( cnt = 0 ; cnt < BACK_INDEX_MAX_COUNT ; cnt++ )
    {
        if ( allocated_memory_array_ex[(int)(position_list[cnt] / MALLOC_POINTER_CACHED_MAX)][position_list[cnt]% MALLOC_POINTER_CACHED_MAX].allocated == allocated )
            remove_heap_index( allocated, position_list[cnt] );
    }
#endif
#endif
    pthread_mutex_unlock(&hashtable_lock);
}

/* -------------------------- allocated memory cache section end ------------------------------------*/

/*
    @desc
    To analyze debug log, we should formalize log format easily to parse.
    
    Debug format follows belows.

jiffies : line lindex : method name : address : size1 : size2

*/
/* -------------------------- print debug section start ------------------------------------*/

// DON'T USE BELOW
/*
void print_hexdecimal(unsigned int value)
{
    unsigned int pointer_calc;
    int index;
    for ( index = 0 ; index < 32 ; index += 4 )
    {
        pointer_calc = value;
        pointer_calc = pointer_calc << index;
        pointer_calc = pointer_calc & 0xf0000000;
        pointer_calc = pointer_calc >> 28;
        pointer_calc = pointer_calc & 0x0000000f;
        if ( pointer_calc > 9 )
            putchar( pointer_calc + 'a' - 10 );
        else 
            putchar( pointer_calc + '0' );
    }
}

void print_debug1(const char* method, void* ptr, int length1, int length2)
{
    unsigned int pointer_calc;
    int index;
    puts(method);
    putchar(':');
    print_hexdecimal((unsigned int)ptr);
    putchar(':');
    print_hexdecimal((unsigned int)length1);
    putchar(':');
    print_hexdecimal((unsigned int)length2);
    putchar('\n');
}
*/

#define BACKTRACE_THREAD_HOLD_SIZE 1000000 // 1M BYTE

#define BIG_TABLE_MANAGER_MAX_ITEM 100 // 500 M 

typedef struct _BIG_TABLE_INFO_ {
    void* allocated;
    MALLOC_FUNC_TYPE_T t_function;
    unsigned long count;
    int length;
    int size;
    int is_deleted;         // After to display it, this value changed from 0 to 1.
} BIG_TABLE_INFO_T;

static BIG_TABLE_INFO_T managed_big_table[BIG_TABLE_MANAGER_MAX_ITEM];

static inline int is_bigtable(MALLOC_INFO_T* item)
{
    int is_big = 0;
    switch ( item->t_function )
    {
    case MALLOC :
        is_big = ( item->length >= BACKTRACE_THREAD_HOLD_SIZE ) ? 1 : 0;
        break;
    case FREE : 
        is_big = ( item->length >= BACKTRACE_THREAD_HOLD_SIZE ) ? 1 : 0;
        break;
    case CALLOC :
        is_big =  ( item->length * item->size >= BACKTRACE_THREAD_HOLD_SIZE ) ? 1 : 0;
        break;
    case REALLOC_FREE : 
        is_big = ( item->length >= BACKTRACE_THREAD_HOLD_SIZE ) ? 1 : 0;;
        break;
    case REALLOC_ALLOC :
        is_big = ( item->length >= BACKTRACE_THREAD_HOLD_SIZE ) ? 1 : 0;
        break;
    case MEMALIGN :
        is_big = ( item->size >= BACKTRACE_THREAD_HOLD_SIZE ) ? 1 : 0;
        break;
    }
    return is_big;
}

static void insert_big_table_info(MALLOC_INFO_T* itemToBeFlushed)
{
    int position = 0;
    if ( itemToBeFlushed->is_deleted )
        return;
    for (; position < BIG_TABLE_MANAGER_MAX_ITEM ; position++ )
    {
        if ( managed_big_table[position].is_deleted || managed_big_table[position].allocated == NULL )
        	{
              managed_big_table[position].allocated = itemToBeFlushed->allocated;
              managed_big_table[position].t_function = itemToBeFlushed->t_function;
              managed_big_table[position].count = itemToBeFlushed->count;
              managed_big_table[position].length = itemToBeFlushed->length;
              managed_big_table[position].size = itemToBeFlushed->size;
              managed_big_table[position].is_deleted = 0;
              break;
        	}
    }
    if ( position >= BIG_TABLE_MANAGER_MAX_ITEM )
  	{
  	    printf("[ERR]--------------------------------------- MAYBE THERE ARE MEMORY LEAK ----------------------------------------");
  	    /*
        for (position = 0; position < BIG_TABLE_MANAGER_MAX_ITEM ; position++ )
        {
            if ( managed_big_table[position].is_deleted || managed_big_table[position].allocated == NULL )
            	{
                  printf("[ERR]  managed_big_table[%d].allocated : %p", position, managed_big_table[position].allocated );
                  printf("[ERR]  managed_big_table[%d].t_function : %d", position, managed_big_table[position].t_function );
                  printf("[ERR]  managed_big_table[%d].count : %d", position, managed_big_table[position].count );
                  printf("[ERR]  managed_big_table[%d].length : %d", position, managed_big_table[position].length );
                  printf("[ERR]  managed_big_table[%d].size : %d", position, managed_big_table[position].size );
                  printf("[ERR]  managed_big_table[%d].is_deleted : %d", position, managed_big_table[position].is_deleted );
            	}
        }
        */
  	}
}

static int delete_from_big_table_info(void* allocated, int* malloc_length)
{
    int position = 0;
    for (; position < BIG_TABLE_MANAGER_MAX_ITEM ; position++ )
    {
        if ( managed_big_table[position].is_deleted || managed_big_table[position].allocated == NULL )
        {
            if ( managed_big_table[position].allocated == allocated )
          	{
                switch( managed_big_table[position].t_function )
                {
                    case  MALLOC :
                  	{
                        *malloc_length = managed_big_table[position].length;
                  	}
                  	break;
                    case  CALLOC :
                  	{
                        *malloc_length = managed_big_table[position].length * managed_big_table[position].size;
                  	}
                  	break;
                    case  REALLOC_ALLOC :
                  	{
                        *malloc_length = managed_big_table[position].length;
                  	}
                  	break;
                    case  MEMALIGN :
                  	{
                        *malloc_length = managed_big_table[position].length;
                  	}
                  	break;
                    case	FREE :
                    case  REALLOC_FREE :
                  	{
                  	}
                    break;
                    default :
                    	DEBUG_PRINTF(LOG_ERROR, "%s there is invalid function type. %d.\n",MALLOC_DEBUG_TAG, managed_big_table[position].t_function);
                }
                printf("%s:------------------- BIG TABLE FREED.(%p) ----------------------\n", allocated );
                managed_big_table[position].is_deleted = 1;
                break;
          	}
        }
    }    
    return position < BIG_TABLE_MANAGER_MAX_ITEM ? position : -1;
}


static char log_buffer_ex[CACHE_PAGE_MAX][MALLOC_POINTER_CACHED_MAX][LOG_BUFFER_MAX_LINE_PER_FUNC][LOG_BUFFER_LINE_LETTER_MAX+1];
#define log_buffer log_buffer_ex[allocated_memory_array_page]

static void flush_log_buffer()
{
    int cnt;
    int depth;
    DEBUG_PUTS(LOG_DEBUG, "flush_log_buffer start.....");
    for (cnt = 0 ; cnt < MALLOC_POINTER_CACHED_MAX ; cnt++ )
    {
        if ( allocated_memory_array[cnt].is_deleted == 0 && allocated_memory_array[cnt].allocated != NULL )
        {
            for (depth = 0 ; depth < LOG_BUFFER_MAX_LINE_PER_FUNC ; depth++ )
            {
                if (strlen(log_buffer[cnt][depth]) > 0)
                    DEBUG_PRINTF(LOG_INFO, log_buffer[cnt][depth]);
            }
        }
    }
    memset(log_buffer, 0x00, sizeof(log_buffer));
}



static void printf_into_log_buffer(int cache_index, int depth, const char* log)
{
    DEBUG_PUTS(LOG_DEBUG, "printf_into_log_buffer start.....");
    memset(log_buffer[cache_index][depth], 0x00, LOG_BUFFER_LINE_LETTER_MAX);
    strncpy(log_buffer[cache_index][depth], log, LOG_BUFFER_LINE_LETTER_MAX);
}

static void backtrace_to_console() {
    void *array[50];
    size_t size;
    char **strings;
    size_t i;
    
    size = backtrace(array, 50);
    
    strings = backtrace_symbols(array,size);
    
    for ( i = 0; i < size ; i++ )
      printf("###:%s", strings[i]);
    free (strings);
}

static void print_stack_trace(MALLOC_FUNC_TYPE_T func_type, int cache_index, unsigned long counter, void* ptr, int length1, int length2)
{
    DEBUG_PUTS(LOG_DEBUG, "print_stack_trace start.....");
    //if ( cache_index < 0 )
    /*
    if ( 1 );
        {} // print_to_display
    else
    */
#if 1
    {
        char line_buffer[1024] = {0, };
        char* method = (func_type == MALLOC ) ? MALLOC_METHOD :
            (func_type == FREE) ? FREE_METHOD :
                (func_type == CALLOC) ? CALLOC_METHOD :
                    (func_type == REALLOC_FREE) ? REALLOC_FREE_METHOD :
                        (func_type == REALLOC_ALLOC) ? REALLOC_ALLOC_METHOD : 
                            (func_type == MEMALIGN) ? MEMALIGN_METHOD : "INVALID";
        void *array[50];
        size_t size;
        char **strings;
        size_t i;
        
        size = backtrace(array, 50);
        
        strings = backtrace_symbols(array,size);
        
        for ( i = 0; i < size ; i++ )
        {
            memset(line_buffer, 0x00, sizeof(line_buffer));
            snprintf(line_buffer, 1024, "%s:%lu:%s:%p:%d:%d:%d:%s", STRACE_DEBUG_TAG, counter, method, ptr, length1, length2, i, strings[i]);
            //puts(line_buffer);
            send_log_by_tcp(line_buffer);
            //DEBUG_PRINTF(LOG_INFO, line_buffer);
        }
        free (strings);
    } // print_into_log_buffer
#endif
}

static int is_backtrace_log_target(MALLOC_FUNC_TYPE_T func_type, int cache_index, unsigned long counter, void* ptr, int length1, int length2)
{
    int need_backtrace = 0;
    static int byte44counter = 1;
    static int byte32counter = 1;
    switch( func_type )
    {
        case  MALLOC :
      	{
      	    if ( length1 >= BACKTRACE_THREAD_HOLD_SIZE )
      	        need_backtrace = 1;
      	}
      	break;
        case  CALLOC :
      	{
      	    if ( length1 * length2 >= BACKTRACE_THREAD_HOLD_SIZE )
      	        need_backtrace = 1;
      	}
      	break;
        case  REALLOC_ALLOC :
      	{
      	    if ( length1 >= BACKTRACE_THREAD_HOLD_SIZE )
      	        need_backtrace = 1;
      	}
      	break;
        case  MEMALIGN :
      	{
      	    if ( length2 >= BACKTRACE_THREAD_HOLD_SIZE )
      	        need_backtrace = 1;
      	}
      	break;
        case	FREE :
        case  REALLOC_FREE :
      	{
      	    if ( length1 >= BACKTRACE_THREAD_HOLD_SIZE )
      	    need_backtrace = 1;
      	}
        break;
        default :
        	DEBUG_PRINTF(LOG_ERROR, "%s there is invalid function type. %d.\n",MALLOC_DEBUG_TAG, func_type);
    }
    return need_backtrace;
}

static int is_skipped_instance( MALLOC_FUNC_TYPE_T func_type, void* ptr, int length1, int length2)
{
    int is_skipped = 0;
    switch( func_type )
    {
        case  MALLOC :
      	{
      	    if ( length1 < 100 )
      	        is_skipped = 1;
      	}
      	break;
        case  CALLOC :
      	{
      	    if ( length1 * length2 < 100 )
      	        is_skipped = 1;
      	}
      	break;
        case  REALLOC_ALLOC :
      	{
      	    if ( length1 < 100 )
      	        is_skipped = 1;
      	}
      	break;
        case  MEMALIGN :
      	{
      	    if ( length2 < 100 )
      	        is_skipped = 1;
      	}
      	break;
        case	FREE :
        case  REALLOC_FREE :
      	{
      	    is_skipped = 0;
      	}
      	{
      	
        }
        break;
        default :
        	DEBUG_PRINTF(LOG_ERROR, "%s there is invalid function type. %d.\n",MALLOC_DEBUG_TAG, func_type);
    }
  	return is_skipped;
}


static void print_format_log(MALLOC_FUNC_TYPE_T func_type, int cache_index, unsigned long counter, void* ptr, int length1, int length2)
{
    DEBUG_PUTS(LOG_DEBUG, "print_format log.....");

    if ( is_skipped_instance( func_type, ptr, length1, length2 ) )
    	return;

    char line_buffer[512] = {0, };
    char* method = (func_type == MALLOC ) ? MALLOC_METHOD :
        (func_type == FREE) ? FREE_METHOD :
            (func_type == CALLOC) ? CALLOC_METHOD :
                (func_type == REALLOC_FREE) ? REALLOC_FREE_METHOD :
                    (func_type == REALLOC_ALLOC) ? REALLOC_ALLOC_METHOD : 
                        (func_type == MEMALIGN) ? MEMALIGN_METHOD : "INVALID";
    snprintf(line_buffer,512, "%s:%lu:%s:%p:%d:%d", MALLOC_DEBUG_TAG, counter, method, ptr, length1, length2);
    if ( cache_index < 0 )
  	{
        DEBUG_PRINTF(LOG_INFO, line_buffer);
  	}
    else
        printf_into_log_buffer(cache_index, 0, line_buffer);
    
}

static pthread_mutex_t debug_print_lock = PTHREAD_MUTEX_INITIALIZER;

void print_debug(MALLOC_FUNC_TYPE_T func_type, void* ptr, int length1, int length2)
{
    DEBUG_PUTS(LOG_DEBUG, "print_debug start.....");
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    long current_time_calculated = current_time.tv_sec * 1000000 + current_time.tv_usec;
    switch( func_type )
    {
        case  MALLOC :
        case  CALLOC :
        case  REALLOC_ALLOC :
        case  MEMALIGN :
      	{
            pthread_mutex_lock(&debug_print_lock);
      	    int hash_index = insert_new_memory_allocation(func_type, current_time_calculated, ptr, length1, length2 );
      	    if ( hash_index < 0 )
    	    	{
    	    	    flush_cache();
    	    	    hash_index = insert_new_memory_allocation(func_type, current_time_calculated, ptr, length1, length2 );
    	    	}
            pthread_mutex_unlock(&debug_print_lock);
      	}
      	break;
        case	FREE :
        case  REALLOC_FREE :
      	{
      	    delete_memory_allocation(func_type, current_time_calculated, ptr, &length1, &length2);
        }
        break;
        default :
        	DEBUG_PRINTF(LOG_ERROR, "%s there is invalid function type. %d.\n",MALLOC_DEBUG_TAG, func_type);
    }
    if ( is_backtrace_log_target( func_type, -1, current_time_calculated, ptr, length1, length2 ) )
        print_stack_trace(func_type, -1, current_time_calculated, ptr, length1, length2);
}
/* -------------------------- print debug section end ------------------------------------*/

/* -------------------------- main method section start ------------------------------------*/
void* malloc (size_t size)
{
    DEBUG_PUTS(LOG_DEBUG, "malloc start...");
    wait_to_finish_init(org_malloc);
    void* new_allocated = org_malloc(size);
    print_debug(MALLOC, new_allocated, size, 0);
    return new_allocated;
}

void free (void* ptr)
{
    DEBUG_PUTS(LOG_DEBUG, "free start...");
    if ( ptr == NULL )
        return;
    if ( ((void*)inner_buffer <= ptr) && (((void*)inner_buffer+4096) > ptr))
    {
        free_with_inner_buffer(ptr);
    }
    else   
    {
        wait_to_finish_init(org_free);
        org_free(ptr);
    }
    print_debug(FREE, ptr, 0, 0);
}

void* calloc (size_t num, size_t size)
{
    DEBUG_PUTS(LOG_DEBUG, "calloc start...");
    void* new_allocated = NULL;
    if ( !org_calloc )
    {
        if ( num * size < 4096 )
            new_allocated = malloc_with_inner_buffer(num * size);
        else
            wait_to_finish_init(org_calloc);
    }
    if ( !new_allocated )
    {
        wait_to_finish_init(org_calloc);
        new_allocated = org_calloc(num, size);
    }
    print_debug(CALLOC, new_allocated, num, size);
    return new_allocated;
}

void* realloc (void* ptr, size_t size)
{
    DEBUG_PUTS(LOG_DEBUG, "realloc start...\n");
    wait_to_finish_init(org_realloc);
    void* new_allocated = org_realloc(ptr, size);
    if ( ptr != NULL )
        print_debug(REALLOC_FREE, ptr, 0, 0);
    print_debug(REALLOC_ALLOC, new_allocated, size, 0);
    return new_allocated;
}

void* memalign(size_t alignment, size_t size)
{
    DEBUG_PUTS(LOG_DEBUG, "memalign start...\n");
    wait_to_finish_init(org_realloc);
    void* new_allocated = org_memalign(alignment, size);
    print_debug(MEMALIGN, new_allocated, size, alignment);
    return new_allocated;
}
/* -------------------------- main method section start ------------------------------------*/
