#ifndef __TSLIB_RW_SEM_H__
#define __TSLIB_RW_SEM_H__

struct kernel_mutex;

struct rw_semaphore
{
	struct kernel_mutex *mutex;
	int reader_count;
};


extern void init_rwsem( struct rw_semaphore *sem);
extern void down_write( struct rw_semaphore *sem);
extern void up_write( struct rw_semaphore *sem);
extern int down_write_trylock( struct rw_semaphore *sem);
extern void down_read( struct rw_semaphore *sem);
extern void up_read( struct rw_semaphore *sem);
extern int down_read_trylock( struct rw_semaphore *sem);
extern void downgrade_write( struct rw_semaphore *sem);

#define down_write_nested( sem, subclass) down_write( sem);
#define down_read_nested( sem, subclass) down_read( sem);

#endif
