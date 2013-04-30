vpath % .. ../tslib ../xfs ../linux
CFLAGS = -I ../ -g -Wall
CC = gcc
OBJS = read_super.o		\
       syscall.o		\
       rbtree.o			\
       xfsd_dir2_sf.o		\
       xfsd_bmap_btree.o	\
       xfsd_dir2_node.o		\
       xfsd_dir2_leaf.o		\
       xfsd_da_btree.o		\
       xfsd_dir2.o 		\
       xfsd_dir2_block.o 	\
       xfsd_dir2_data.o 	\
       sort.o 			\
       xfsd_message.o 		\
       xfsd_error.o 		\
       xfsd_attr_leaf.o 	\
       xfsd_attr.o 		\
       xfsd_inode.o 		\
       xfsd_buf.o 		\
       xfsd_bmap.o 		\
       xfsd_btree.o 		\
       xfsd_alloc.o 		\
       xfsd_ialloc.o 		\
       xfsd_alloc_btree.o 	\
       xfsd_ialloc_btree.o 	\
       xfsd_mount.o 		\
       xfsd_mem.o 		\
       xfsd_super.o 		\
       xfsd_trans.o 		\
       process.o 		\
       radix-tree.o 		\
       sema.o 			\
       disk.o 			\
       rwsem.o 			\
       xfsd_icache.o 		\
       xfsd_uuid.o 		\
       tslib.o 			\
       read_file2.o		
	

hello: hello.c $(OBJS)
	$(CC) -I ../ -g -Wall -lpthread $< $(OBJS) -o $@

clean:
	rm -f hello
	rm -f *.o
	rm -f *.d

%.d: %.c makefile
	bash -ec '$(CC) -MM $(CFLAGS) $< | sed '\''s/\($*\.o\)[ :]*/\1 $@ : /g'\'' > $@'

-include $(OBJS:.o=.d)

