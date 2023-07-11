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

//    if(!page_ptr){
//        printf("NOT VALID!: 0x%x\n", addr);
//    }
    return page_ptr != NULL;
}
//
//static void
//syscall_handler2 (struct intr_frame *f UNUSED)
//{
//    printf("System Call!\n");
//    struct thread *t = thread_current ();
//    if(t){
//        printf("%s: exit(%d)\n", t->name, t->exit_status);
//    } else {
//        printf("T is bad!\n");
//    }
//
//    thread_exit ();
//    //thread_exit();
//    return;
//    int *esp = (int*)f->esp;
////    if (!is_valid_addr(p))
////        exit_handler(-1);
////  hex_dump(f->esp, f->esp, 50, true);
//    int number = *esp;
//    //printf("number: %d\n", number);
//    esp += 1;
//
//    bool b_handled = false;
//
//    switch(number){
//        case SYS_HALT:                   /* Halt the operating system. */
//            halt_handler();
//            break;
//        case SYS_EXIT:
//        {
//
////            printf("SYS_EXIT\n");
////            //hex_dump(f->esp, f->esp, 80, true);
////            if(!is_user_vaddr (esp)){
////                //b_handled = true;
////                // printf("Invalid virtual address: 0x%x\n", esp);
//////              exit_handler(-1);
////            }
////            {
////                //this is what makes it not spin
////                int* status_ptr = esp;
////                exit_handler(*status_ptr);
////            }
////            b_handled = true;
//        }
//            break;
////        case SYS_EXEC:                   /* Start another process. */
////            break;
////        case SYS_WAIT:                   /* Wait for a child process to die. */
////            break;
////        case SYS_CREATE:                 /* Create a file. */
////            break;
////        case SYS_REMOVE:                 /* Delete a file. */
////            break;
////        case SYS_OPEN:                   /* Open a file. */
////            break;
////        case SYS_FILESIZE:               /* Obtain a file's size. */
////            break;
////        case SYS_READ:                   /* Read from a file. */
////            break;
//        case SYS_WRITE: /* Write to a file. */
//        {
//            printf("SYS_WRITE\n");
//            //hex_dump(f->esp, f->esp, 50, true);
//            int fd = *esp;
//            esp += 1;
////            if (!is_valid_addr(esp))
////                exit_handler(-1);
//            char *buffer = *esp;
//            esp += 1;
//            unsigned size = *esp;
//            esp += 1;
//            //printf("fd: %d, buffer: %s, buffer address: 0x%x,  size: %d\n", fd, buffer, buffer, size);
//            f->eax = write_handler(fd, buffer, size);
//            b_handled = true;
//        }
//            break;
////        case SYS_SEEK:                   /* Change position in a file. */
////            break;
////        case SYS_TELL:                   /* Report current position in a file. */
////            break;
////        case SYS_CLOSE:                  /* Close a file. */
////            break;
//        default:
//            printf ("unknown syscall: %d\n", number);
//            b_handled = true;
//            break;
//    }
//
//    if(!b_handled)
//        thread_exit();
//
////------------------------------------------------------------------
//
//
//
////  printf ("system call!\n");
////    int* esp = (int*)f->esp;
//    //hex_dump(f->esp, f->esp, 50 , true);
////    printf("0x%x\n", *(esp ));
////    printf("0x%x\n", *(esp + 1));
////
////  if(!is_user_vaddr (*(esp+1))){
////      printf("Invalid virtual addrss\n");
////  }
////  if(!is_valid_addr(*(esp+1)))
////    exit_handler(-1);
////    thread_exit();
//
////to get the sc-bad-sp tp print
//    //thread_exit();
////    exit_handler(-1);
//}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int *esp = (int*)f->esp;
    if (!is_valid_addr(esp))
        exit_handler(-1);
//  hex_dump(f->esp, f->esp, 50, true);
  int number = *esp;
  //printf("number: %d\n", number);
  esp += 1;

  bool b_handled = false;

    switch(number){
      case SYS_HALT:                   /* Halt the operating system. */
          halt_handler();
          break;
      case SYS_EXIT:
      {
          //printf("SYS_EXIT\n");
          //hex_dump(f->esp, f->esp, 80, true);
          if(!is_user_vaddr (esp)){
              //b_handled = true;
              // printf("Invalid virtual address: 0x%x\n", esp);
//              exit_handler(-1);
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
//          printf("In sys write....");

          //hex_dump(f->esp, f->esp, 50, true);
          int fd = *esp;
          esp += 1;
          if (!is_valid_addr(esp))
              exit_handler(-1);
          char *buffer = *esp;
          esp += 1;
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




