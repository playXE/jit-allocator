#include <stdio.h> 
#include <fcntl.h>          
#include <unistd.h>         
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>        
#include <sys/types.h>

int main()  
{
        // Lets do this demonstration with one megabyte of memory:
        const int len = 1024*1024;

        // create shared memory object:
        int fd = shm_open("/myregion", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
        printf ("file descriptor is %d\n", fd);

        // set the size of the shared memory object:
        if (ftruncate(fd, len) == -1)
        {
            printf ("setting size failed\n");
            return 0;
        }

        // Now get two pointers. One with read-write and one with read-only.
        // These two pointers point to the same physical memory but will
        // have different virtual addresses:

        char * rw_data = mmap(0, len, PROT_READ|PROT_WRITE, MAP_SHARED, fd,0);
        char * ro_data = mmap(0, len, PROT_READ           , MAP_SHARED, fd,0);

        printf ("rw_data is mapped to address %p\n", rw_data);
        printf ("ro_data is mapped to address %p\n", ro_data);

        // ===================
        // Simple test-bench:
        // ===================

        // try writing:
        strcpy (rw_data, "hello world!");

        if (strcmp (rw_data, "hello world!") == 0)
        {
            printf ("writing to rw_data test passed\n");
        } else {
            printf ("writing to rw_data test failed\n");
        }

        // try reading from ro_data
        if (strcmp (ro_data, "hello world!") == 0)
        {
            printf ("reading from ro_data test passed\n");
        } else {
            printf ("reading from ro_data test failed\n");
        }

        printf ("now trying to write to ro_data. This should cause a segmentation fault\n");

        // trigger the segfault
        ro_data[0] = 1;

        // if the process is still alive something didn't worked.
        printf ("writing to ro_data test failed\n");
        return 0;
}