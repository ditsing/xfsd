#ifdef WIN32
#error "what's the fuck!"
#else

struct mutex
{
	struct kernel_mutex *kmutex;
};
typedef struct mutex mutex_t;

void mutex_lock( mutex_t *);
void mutex_unlock( mutex_t *);
int mutex_trylock( mutex_t *);
void mutex_init( mutex_t *);

extern struct kernel_mutex inline_kmutex;
#define DEFINE_MUTEX(x) mutex_t x = { &inline_kmutex};

#endif
