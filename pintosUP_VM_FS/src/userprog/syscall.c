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
int read_handler(int fd, char* buffer, unsigned size);
int filesize_handler(int fd);
void seek_handler(int fd, unsigned position);
unsigned tell_handler(int fd);
bool remove_handler(const char* filename);

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
   // printf("Thread: %s, id: %d, Number: %d\n", thread_current()->name, thread_current ()->tid, number);

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
      {
          //printf("ticks: %llu, Executing... \n", timer_ticks ());
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
          // printf(" ======== Executing in thread: %d, filename: %s\n", thread_current() ->tid, filename);
          f->eax = process_execute (filename);

          b_handled = true;
      }
          break;
      case SYS_WAIT:                   /* Wait for a child process to die. */
      {
         // printf("ticks: %jd, Waiting...\n", timer_ticks ());
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          tid_t thread_id = *esp;

          struct thread* cur = thread_current ();
          //printf("sys_wait handler start, %d waiting for %d\n", cur->status, cur->tid, thread_id);
          f->eax = process_wait(thread_id);
          //printf("sys_wait handler end\n");
          //printf("current status: %d, current id: %d\n", cur->status, cur->tid);
          b_handled = true;
      }
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
      {
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          const char* filename = *esp;
          if(!is_valid_range((void*)filename, (void*)filename + 3)) {
              b_handled = true;
              exit_handler(-1);
          }

          f->eax = remove_handler(filename);

          b_handled = true;
      }
          break;
      case SYS_OPEN:                   /* Open a file. */
      {
          //printf("Opening... \n");
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
            //printf("Successfully Opened... \n");
          b_handled = true;
      }
          break;
      case SYS_FILESIZE:               /* Obtain a file's size. */
      {
          //printf("Filesize... \n");
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              //printf("Not valid ptr\n");
              b_handled = true;
              exit_handler(-1);
          }
          int fd = *esp;

          f->eax = filesize_handler(fd);

          b_handled = true;
      }
          break;
      case SYS_READ:                   /* Read from a file. */
      {
          //printf("Reading... \n");

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
          char* buffer = *esp;
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

          f->eax = read_handler(fd, buffer, size);

          b_handled = true;
      }
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
          unsigned position = *esp;

          seek_handler(fd, position);

          b_handled = true;
      }
          break;
      case SYS_TELL:                   /* Report current position in a file. */
      {
          esp += 1;
          if(!is_valid_range((void*)esp, (void*)esp + 3)) {
              b_handled = true;
              exit_handler(-1);
          }
          int fd = *esp;

          f->eax = tell_handler(fd);

          b_handled = true;
      }
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
    report_status (CS_KILLED, false);
    printf("%s: exit(%d)\n", t->name, t->exit_status);
    thread_exit ();
}

int
write_handler (int fd, const void* buffer, unsigned size) {
    int bytes_written = 0;
    if(fd <= 0 || fd > 63)
        return bytes_written;

    if(fd == 1){
        putbuf(buffer, size);
        bytes_written = size;
        return bytes_written;
    }

    lock_acquire (&file_sys_lock);
    struct file* file_ = thread_current ()->file_dt[fd];
    if(file_) {
        bytes_written = file_write(file_, buffer, size);
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
    file_close(file_);
    thread_current ()->file_dt[fd] = NULL;

//    print_counts(file_);
//    int deny_cnt = file_->inode->deny_write_cnt;
//    int open_cnt = file_->inode->open_cnt;
//    printf("deny_write_cnt: %d, inode_open_cnt: %d\n", deny_cnt, open_cnt);
    lock_release (& file_sys_lock);
}

int read_handler(int fd, char* buffer, unsigned size) {
    unsigned bytes_read = -1;

    if(fd < 0 || fd == 1 || fd > 63)
        return bytes_read;



    if(fd == 0) {
        char* curr_char = buffer;
        bytes_read = 0;
        while(size > 0) {
            *curr_char = input_getc ();
            curr_char++;
            if(curr_char = '\n')
                break;
            bytes_read++;
        }
        return bytes_read;
    }
    lock_acquire (& file_sys_lock);
    struct file* file_ = thread_current ()->file_dt[fd];
    if(file_)
        bytes_read = file_read(file_, buffer, size);
    lock_release (& file_sys_lock);
    return bytes_read;
}


int filesize_handler(int fd) {
    int filesize = 0;
    if(fd < 2 || fd > 63)
        return 0;

    lock_acquire (& file_sys_lock);
    struct file* file_ = thread_current ()->file_dt[fd];
    if(file_){
        filesize = file_length(file_);
    }
    lock_release (& file_sys_lock);
    return filesize;
}

void seek_handler(int fd, unsigned position) {
    if(fd < 2 || fd > 63)
        return;

    lock_acquire (& file_sys_lock);
    struct file* file_ = thread_current ()->file_dt[fd];
    if(file_){
        file_seek(file_, position);
    }
    lock_release (& file_sys_lock);
}

unsigned tell_handler(int fd) {
    unsigned pos = -1;

    if(fd < 2 || fd > 63)
        return pos;

    lock_acquire (& file_sys_lock);
    struct file* file_ = thread_current ()->file_dt[fd];
    if(file_){
        pos = file_tell(file_);
    }
    lock_release (& file_sys_lock);
    return pos;
}

bool remove_handler(const char* filename) {
    lock_acquire (& file_sys_lock);
    filesys_remove(filename);
    lock_release (& file_sys_lock);
}