//
// Created by dustin on 8/6/23.
//


#ifndef PINTOS_UBUNTU_PAGE_H
#define PINTOS_UBUNTU_PAGE_H


#include "stdbool.h"
#include "stdint.h"
#include "threads/thread.h"
#include <hash.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"


enum page_type {
    PT_ELF, //Text, Data
    PT_FILE, //mmap'd()
    PT_SWAP, //pages in swap file
    PT_ANONYMOUS //stack, heap
};

struct vm_entry {
    struct hash_elem h_elem;
    uint32_t VPN;
    bool write;
    enum page_type p_type;
    struct file* file_ptr;
    uint64_t offset;
    uint64_t size; //size of data inside page
    bool in_memory;
};

struct vm_entry* vm_entry_init (uint32_t VPN, bool write, enum page_type p_type, struct file* file_ptr,
                      uint64_t offset, uint64_t size, bool in_memory);

/* Returns a hash value for page p. */
unsigned page_hash (const struct hash_elem *h_elem_ptr, void *aux UNUSED);

/* Returns true if page a precedes page b. */
bool page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);

void free_hash_elem (struct hash_elem *e, void *aux);

/*
- Virtual Page Number
- Read/Write Permission
- Type of virtual page:
    - page of ELF executable (must deny write)
    - page of general file (file backed)
    - page of swap area (anonymous)
- Reference to file object and offset (memory mapped file)
- Amount of data in the page
- Location in swap area (redundant, already have offset in swap file)
- In-memory flag: is it in memory?
 * */
#endif //PINTOS_UBUNTU_PAGE_H
