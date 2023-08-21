#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "vm/page.h"

void exit_handler(int status);

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  Shouldn't happen.  Panic the
         kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to project 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

#ifdef VM

// Original Code


//  exit_handler(-1);
//
//    /* To implement virtual memory, delete the rest of the function
//       body, and replace it with code that brings in the page to
//       which fault_addr refers. */
//    printf ("Page fault at %p: %s error %s page in %s context.\n",
//            fault_addr,
//            not_present ? "not present" : "rights violation",
//            write ? "writing" : "reading",
//            user ? "user" : "kernel");
//    kill (f);
// Original Code

//  exit_handler(-1);
//
//  /* To implement virtual memory, delete the rest of the function
//     body, and replace it with code that brings in the page to
//     which fault_addr refers. */
//  printf ("Page fault at %p: %s error %s page in %s context.\n",
//          fault_addr,
//          not_present ? "not present" : "rights violation",
//          write ? "writing" : "reading",
//          user ? "user" : "kernel");
//  kill (f);

    // TODO more rigorous checking of fault_addr
    // such as if its a kernel or user address, etc
    // and fail if address invalid
    bool valid = true;
    my_print2(EXCEPTION_LOGGING, "f_addr: 0x%x\n", fault_addr);
    void* f_addr = pg_round_down(fault_addr);
    my_print2(EXCEPTION_LOGGING, "Round down f_addr: 0x%x\n", f_addr);
    if(!valid) {
        //printf("No valid adress");
        page_fault_fail(f);
        NOT_REACHED();
    }

    struct vm_entry temp;
    temp.VPN = f_addr;

    struct hash_elem* h_elem_ptr = hash_find(& thread_current ()->vm, & temp);
    if(! h_elem_ptr) {
        //printf("Table entry not found\n");
        page_fault_fail(f);
        NOT_REACHED();
    }

    struct vm_entry *found_page = hash_entry(h_elem_ptr, struct vm_entry, h_elem);

    bool success = handle_mm_fault(found_page);

    if(!success) {
        page_fault_fail(f);
        NOT_REACHED();
    }


#else  // VM
    exit_handler(-1);

    /* To implement virtual memory, delete the rest of the function
       body, and replace it with code that brings in the page to
       which fault_addr refers. */
    printf ("Page fault at %p: %s error %s page in %s context.\n",
            fault_addr,
            not_present ? "not present" : "rights violation",
            write ? "writing" : "reading",
            user ? "user" : "kernel");
    kill (f);
#endif  // VM
}




#ifdef VM
bool handle_mm_fault(struct vm_entry* vme) {
    uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL){
         // printf("Failed to allocate page\n");
          palloc_free_page (kpage);
          return false;
      }


    if(vme->p_type != PT_ELF) {
        //printf("Not binary\n");
         palloc_free_page (kpage);
         return false;
    }

    bool success = load_file (kpage, vme);
    if(!success)
         palloc_free_page (kpage);

    return success;
}

bool load_file (uint8_t* kpage, struct vm_entry* vme) {
     /* Load this page. */
     struct file* file = vme->file_ptr;
     uint64_t offset = vme->offset;

     size_t page_read_bytes = vme->size < PGSIZE ? vme->size : PGSIZE;
     size_t page_zero_bytes = PGSIZE - page_read_bytes;

      if (file_read_at (file, kpage, page_read_bytes, offset) != (int) page_read_bytes)
        {
          //printf("Failed to read whole page\n");
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
      my_print3(EXCEPTION_LOGGING, "Installing page- begin: 0x%x, end: 0x%x \n", vme->VPN, vme->VPN + PGSIZE);
//      /* Add the page to the process's address space. */
      if (!install_page_wrapper (vme->VPN, kpage, vme->write))
        {
          //printf("Failed to install page\n");
          return false;
        }

      return true;
}


void page_fault_fail(struct intr_frame *f) {
    exit_handler(-1);
    kill(f);
    NOT_REACHED();
}
#endif //VM

