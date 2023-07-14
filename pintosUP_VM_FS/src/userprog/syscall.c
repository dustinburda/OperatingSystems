#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
void halt_handler ();
void exit_handler (int status);
int write_handler (int fd, const void* buffer, unsigned size);
bool create_handler(const char* filename, unsigned size);
int open_handler(const char* filename);
void close_handler(int fd);

static bool is_valid_addr(void* addr);

struct lock file_sys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_sys_lock);
}

static bool
is_valid_range(void* addr_begin, void* addr_end) {
//    printf("Is valid range\n");
    bool begin = is_valid_addr (addr_begin);
//    printf("begin addr: 0x%x, begin bool: %d\n", addr_begin, begin != 0);
    bool end = is_valid_addr(addr_end);
//    printf("end: 0x%x, end bool: %d\n", addr_end, end != 0);
    return begin && end;
}

static bool
is_valid_addr(void* addr) {
//    printf("is_valid_addr, addr: 0x%x\n", addr);
    if(!addr){
//        printf("NULL!: 0x%x\n", addr);
        return false;
    }

    if(!is_user_vaddr (addr)) {
        return false;
    }

//    uint32_t* page_ptr = page_lookup (thread_current ()->pagedir, addr);
    uint32_t* page_ptr = pagedir_get_page(thread_current ()->pagedir, addr);

//    if(!page_ptr){
////        printf("Not valid address!: 0x%x\n", addr);
//    }
    return page_ptr != NULL;
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{
    int *esp = (int*)f->esp;
    if(!is_valid_range(f->esp, f->esp + 3))
        exit_handler(-1);
    // hex_dump(f->esp, f->esp, 80, true);
    int number = *esp;
//    esp += 1;

    bool b_handled = false;

    switch(number){
      case SYS_HALT:                   /* Halt the operating system. */
          halt_handler();
          break;
      case SYS_EXIT:
      {
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          {
              //this is what makes it not spin
              int* status_ptr = esp;
              exit_handler(*status_ptr);
          }
          b_handled = true;
      }
            break;
      case SYS_EXEC:                   /* Start another process. */
          break;
      case SYS_WAIT:                   /* Wait for a child process to die. */
          break;
      case SYS_CREATE:                 /* Create a file. */
      {
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          char* filename = *esp;
          if(!is_valid_range((void*)filename, (void*)filename + 3)) {
              b_handled = true;
              exit_handler(-1);
          }

          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          unsigned size = *esp;

          f->eax = create_handler(filename, size);

          b_handled = true;
      }
          break;
      case SYS_REMOVE:                 /* Delete a file. */
          break;
      case SYS_OPEN:                   /* Open a file. */
      {
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              //printf("Not valid ptr\n");
              b_handled = true;
              exit_handler(-1);
          }
          const char* filename = *esp;
          if(!is_valid_range((void*)filename, (void*)filename + 3)) {
              //printf("Not valid filename ptr\n");
              b_handled = true;
              exit_handler(-1);
          }

          f->eax = open_handler(filename);

          b_handled = true;
      }
          break;
      case SYS_FILESIZE:               /* Obtain a file's size. */
          break;
      case SYS_READ:                   /* Read from a file. */
          break;
      case SYS_WRITE: /* Write to a file. */
      {
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          int fd = *esp;

          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          char *buffer = *esp;
          if(!is_valid_range((void*)buffer, (void*)buffer + 3)) {
              b_handled = true;
              exit_handler(-1);
          }

          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          unsigned size = *esp;

          esp += 1;
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
      {
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              //printf("Not valid ptr\n");
              b_handled = true;
              exit_handler(-1);
          }
          int fd = *esp;

          close_handler(fd);

          b_handled = true;
      }
          break;
      default:
          printf ("unknown syscall: %d\n", number);
          break;
    }

    if(!b_handled)
        thread_exit();

//------------------------------------------------------------------
}

void
halt_handler() {
    shutdown_power_off ();
}

void
exit_handler(int status) {
    struct thread *t = thread_current ();
    t->exit_status = status;
    printf("%s: exit(%d)\n", t->name, t->exit_status);
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


bool create_handler(const char* filename, unsigned size) {
    bool created = false;

    lock_acquire (& file_sys_lock);
    created = filesys_create (filename, size);
    lock_release (& file_sys_lock);

    return created;
}

int open_handler(const char* filename) {
    int fd = -1;

    lock_acquire (& file_sys_lock);
    struct file* opened_file = filesys_open(filename);
    if(opened_file) {
        int next_fd = thread_current ()->next_fd;
        thread_current ()->next_fd++;
        thread_current ()->file_dt[next_fd] = opened_file;
        fd = next_fd;
    }
    lock_release (& file_sys_lock);

    return fd;
}

void close_handler(int fd) {
    if(fd < 2 || fd > 63)
        return;

    lock_acquire (& file_sys_lock);
    struct file* file_ = thread_current ()->file_dt[fd];
    print_counts(file_);
//    int deny_cnt = file_->inode->deny_write_cnt;
//    int open_cnt = file_->inode->open_cnt;
//    printf("deny_write_cnt: %d, inode_open_cnt: %d\n", deny_cnt, open_cnt);
    lock_release (& file_sys_lock);
}

