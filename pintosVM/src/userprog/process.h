#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include <stdbool.h>

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void report_status(enum child_status status, bool b_exit);
void child_record_init (struct c_record* child_record, tid_t tid);
bool install_page_wrapper(void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
