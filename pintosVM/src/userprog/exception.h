#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

#include <stdbool.h>
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/interrupt.h"
#include "userprog/process.h"

void exception_init (void);
void exception_print_stats (void);

#ifdef VM
bool handle_mm_fault(struct vm_entry* vme);
void page_fault_fail(struct intr_frame *f);
bool load_file (uint8_t* kpage, struct vm_entry* vme);
#endif // VM


#endif /* userprog/exception.h */
