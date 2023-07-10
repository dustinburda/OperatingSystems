#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

void syscall_init (void);


void halt_handler ();
void exit_handler (int status);
bool create_handler(char* file_name, unsigned size);
bool remove_handler(char* file_name);
int open_handler (char* file_name);
int filesize_handler(int fd);
int read_handler (int fd, void* buffer, unsigned size);
int write_handler (int fd, const void* buffer, unsigned size);
void seek_handler (int fd, unsigned position);
unsigned tell_handler(int fd);
void close_handler (int fd);

static bool is_valid_addr(void* addr);


#endif /* userprog/syscall.h */
