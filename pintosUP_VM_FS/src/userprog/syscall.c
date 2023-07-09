#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"

static void syscall_handler (struct intr_frame *);
void halt_handler ();
void exit_handler (int status);
int write_handler (int fd, const void* buffer, unsigned size);

static bool is_valid_addr(void* addr);

struct lock file_sys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_sys_lock);
}

static bool
is_valid_addr(void* addr){
    uint32_t* page_ptr = page_lookup (thread_current ()->pagedir, addr);
    return page_ptr != NULL;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *p = (int*)f->esp;
//  hex_dump(f->esp, f->esp, 50, true);
  int number = *p;
  //printf("number: %d\n", number);
  p += 1;

  bool b_handled = false;

    switch(number){
      case SYS_HALT:                   /* Halt the operating system. */
          halt_handler();
          break;
      case SYS_EXIT:
      {
          int* status_ptr = p;
          exit_handler(*status_ptr);
          b_handled = true;
      }
            break;
      case SYS_EXEC:                   /* Start another process. */
          break;
      case SYS_WAIT:                   /* Wait for a child process to die. */
          break;
      case SYS_CREATE:                 /* Create a file. */
          break;
      case SYS_REMOVE:                 /* Delete a file. */
          break;
      case SYS_OPEN:                   /* Open a file. */
          break;
      case SYS_FILESIZE:               /* Obtain a file's size. */
          break;
      case SYS_READ:                   /* Read from a file. */
          break;
      case SYS_WRITE: /* Write to a file. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          int fd = *p;
          p += 1;
          if (!is_valid_addr(p))
              exit_handler(-1);
          char *buffer = *p;
          p += 1;
          unsigned size = *p;
          p += 1;
          //printf("fd: %d, buffer: %s, buffer address: 0x%x,  size: %d\n", fd, buffer, buffer, size);
          f->eax = write_handler(fd, buffer, size);
          b_handled = true;
      }
          break;
      case SYS_SEEK:                   /* Change position in a file. */
          break;
      case SYS_TELL:                   /* Report current position in a file. */
          break;
      case SYS_CLOSE:                  /* Close a file. */
          break;
      default:
          printf ("unknown syscall: %d\n", number);
          break;
    }

  //printf ("system call!\n");
  if(!b_handled)
      thread_exit();
}

void
halt_handler() {
    shutdown_power_off ();
}

void
exit_handler(int status) {
    struct thread *t = thread_current ();
    t->status = status;
    thread_exit ();
}

int
write_handler (int fd, const void* buffer, unsigned size) {
    if(fd == 0) return 0;

    int bytes_written = 0;
    lock_acquire (&file_sys_lock);
    if(fd == 1){
        bytes_written = size;
        putbuf(buffer, size);
    } else if (fd > 1 && fd < 64) {
        bytes_written = (int)file_write(thread_current ()->file_dt[fd], buffer, size);
    }
    lock_release (&file_sys_lock);
    return bytes_written;
}




