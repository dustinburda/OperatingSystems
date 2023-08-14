//
// Created by dustin on 8/6/23.
//

#include "vm/page.h"


struct vm_entry* vm_entry_init (uint32_t VPN, bool write, enum page_type p_type, struct file* file_ptr,
                                uint64_t offset, uint64_t size, bool in_memory) {

    struct vm_entry* p_vpage = malloc(PGSIZE);

    p_vpage->VPN = VPN;
    p_vpage->write = write;
    p_vpage->p_type = p_type;
    p_vpage->file_ptr = file_ptr;
    p_vpage->offset = offset;
    p_vpage->size = size;
    p_vpage->in_memory = in_memory;

    return p_vpage;
}

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *h_elem_ptr, void *aux UNUSED)
{
    const struct vm_entry *entry_ptr = hash_entry (h_elem_ptr, struct vm_entry, h_elem);
    return hash_int (entry_ptr->VPN);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
    const struct vm_entry *a = hash_entry (a_, struct vm_entry, h_elem);
    const struct vm_entry *b = hash_entry (b_, struct vm_entry, h_elem);

    return a->VPN < b->VPN;
}

void free_hash_elem (struct hash_elem *e, void *aux) {
    // TODO: Need to deallocate resources (maybe)
    struct vm_entry* vm_elem = hash_entry (e, struct vm_entry, h_elem);
    free(vm_elem);
}
