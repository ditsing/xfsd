vpath % .. ../tslib ../xfs ../linux
CFLAGS = -I ../ -g
CC = gcc
OBJS = read_super.o		\
       syscall.o		\
       rbtree.o			\
       read_file.o		\
       xfsd_dir2_sf.o		\
       xfsd_bmap_btree.o	\
       xfsd_dir2_node.o		\
       xfsd_dir2_leaf.o		\
       xfsd_da_tree.o		\
       xfsd_dir2.o 		\
       xfsd_dir2_block.o 	\
       xfsd_dir2_data.o

hello: hello.c $(OBJS)

dll: read_super.o syscall.o read_file.o xfsd_dir2_sf.o xfsd_bmap_btree.o
	$(CC) $(CFLAGS) -shared -fpic read_super.o syscall.o read_file.o xfsd_dir2_sf.o xfsd_bmap_btree.o -o xfsd.dll

clean:
	rm -f hello
	rm -f *.o
