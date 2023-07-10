#include "userprog/syscall.h"
#include <stdio.h>
//#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"

#include "syscall.h"

static void syscall_handler (struct intr_frame *);

struct lock file_sys_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_sys_lock);
}

static bool
is_valid_addr(void* addr){
    if(addr == NULL)
        return false;

//    if(!is_user_vaddr (addr))
//        return false;

    uint32_t* page_ptr = page_lookup (thread_current ()->pagedir, addr);
    return page_ptr != NULL;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *p = (int*)f->esp;
  if(!is_valid_addr(p)){
      exit_handler(-1);
  }
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
          int status_ptr = *p;
          p += 1;
          exit_handler(status_ptr);
          b_handled = true;
      }
            break;
      case SYS_EXEC:                   /* Start another process. */
      {
          if(!is_valid_addr(p))
              exit_handler(-1);
          char* filename = *p;
          p += 1;
          tid_t process_id = process_execute (filename);
          sema_down (&thread_current ()->load_finished);
          if(process_id == TID_ERROR || thread_current ()->load_success == false){
              f->eax = -1;
          } else {
              f->eax = process_id;
          }
          b_handled = true;
      }
          break;
      case SYS_WAIT:                   /* Wait for a child process to die. */
      {
          tid_t pid = *p;
          p += 1;
          int child_id = process_wait(pid);
          f->eax = child_id;
          b_handled = true;
      }
          break;
      case SYS_CREATE:                 /* Create a file. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          if(!is_valid_addr(p))
              exit_handler(-1);
          char* file_name = *p;
          p += 1;
          unsigned size = *p;
          p += 1;
          f->eax = create_handler(file_name, size);
          b_handled = true;
      }
          break;
      case SYS_REMOVE:                 /* Delete a file. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          if(!is_valid_addr(p))
              exit_handler(-1);
          char* file_name = *p;
          p += 1;
          f->eax = remove_handler(file_name);
          b_handled = true;
      }
          break;
      case SYS_OPEN:                   /* Open a file. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          if(!is_valid_addr(p))
              exit_handler(-1);
          char* file_name = *p;
          p += 1;
          int fd = open_handler(file_name);
          if(fd == -1)
              exit_handler(-1);
          f->eax = fd;
          b_handled = true;
      }
          break;
      case SYS_FILESIZE:               /* Obtain a file's size. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          int fd = *p;
          p += 1;
          int size = filesize_handler(fd);
          if(size == -1)
              exit_handler(-1);
          f->eax = size;
          b_handled = true;
      }
          break;
      case SYS_READ:                   /* Read from a file. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          int fd = *p;
          p += 1;
          // check if buffer ptr is valid
          if(!is_valid_addr(p))
              exit_handler(-1);
          void* buffer = *p;
          p += 1;
          unsigned size = *p;
          p +=1;
          f->eax = read_handler (fd, buffer, size);
          b_handled = true;
      }
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
      {
          //hex_dump(f->esp, f->esp, 50, true);
          int fd = *p;
          p += 1;
          unsigned position = *p;
          p += 1;
          seek_handler(fd, position);
          b_handled = true;
      }
          break;
      case SYS_TELL:                   /* Report current position in a file. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          int fd = * p;
          p += 1;
          unsigned next_byte = tell_handler(fd);
          if(next_byte == -1)
              exit_handler(-1);
          f->eax = next_byte;
          b_handled = true;
      }
          break;
      case SYS_CLOSE:                  /* Close a file. */
      {
          //hex_dump(f->esp, f->esp, 50, true);
          int fd = * p;
          p += 1;
          close_handler(fd);
          b_handled = true;
      }
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
    printf ("%s: exit(%d)\n", t->name, t->status);
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

bool create_handler(char* file_name, unsigned size) {
    bool created = false;
    lock_acquire (&file_sys_lock);
    created = filesys_create (file_name, size);
    lock_release (&file_sys_lock);
    return created;
}

bool remove_handler(char* file_name){
    bool closed = false;
    lock_acquire (&file_sys_lock);
    closed = filesys_remove (file_name);
    lock_release (&file_sys_lock);
    return closed;
}

int open_handler (char* file_name) {
    int fd = -1;

    if(thread_current ()->next_fd == MAX_FILES)
        return fd;

    lock_acquire (&file_sys_lock);
    struct file* open_file = filesys_open (file_name);
    if(open_file != NULL){
        fd = thread_current() ->next_fd;
        thread_current() ->next_fd++;
        thread_current()->file_dt[fd] = open_file;
    }
    lock_release (&file_sys_lock);

    return fd;
}

int filesize_handler(int fd){
    int size = -1;

    if(fd < 0 || fd > MAX_FILES)
        return size;

    struct file* file_ = thread_current() ->file_dt[fd];
    if(file_ == NULL)
        return size;

    lock_acquire (& file_sys_lock);
    size = file_length (file_);
    lock_release (& file_sys_lock);

    return size;
}

int read_handler (int fd, void* buffer, unsigned size){
    int r_size = -1;

    if(fd < 0 || fd >= MAX_FILES || fd == 1)
        return r_size;


    if(fd == 0){
        r_size = 0;
        char* buffer_ = (char*)buffer;
        for(int i =0; i < size; i++){
            uint8_t character = input_getc();
            if(character == 13){
                break;
            }
            *buffer_ = character;
            buffer_++;
            r_size++;
        }
        *buffer_ = 0;
        return r_size;
    }

    lock_acquire (& file_sys_lock);
    struct file* file_ = thread_current() ->file_dt[fd];
    if(file_ != NULL){
        r_size = file_read (file_, buffer, size);
    }
    lock_release (& file_sys_lock);
    return r_size;
}

void seek_handler (int fd, unsigned position){
    if(fd < 0 || fd >= MAX_FILES || fd == 1 || fd == 0)
        return;

    struct file* file_ = thread_current() ->file_dt[fd];
    if(file_ == NULL)
        return;

    lock_acquire (&file_sys_lock);
    file_seek(file_, position);
    lock_release (&file_sys_lock);
}

unsigned tell_handler(int fd){
    if(fd < 0 || fd >= MAX_FILES || fd == 1 || fd == 0)
        return -1;

    struct file* file_ = thread_current() ->file_dt[fd];
    if(file_ == NULL)
        return -1;

    unsigned next_byte;
    lock_acquire (&file_sys_lock);
    next_byte = file_tell (file_);
    lock_release (&file_sys_lock);
    return next_byte;
}

void close_handler (int fd){
    if(fd < 0 || fd >= MAX_FILES || fd == 1 || fd == 0)
        return;

    struct file* file_ = thread_current() ->file_dt[fd];
    if(file_ == NULL)
        return;

    lock_acquire (&file_sys_lock);
    file_close (file_);
    lock_release (&file_sys_lock);
}


