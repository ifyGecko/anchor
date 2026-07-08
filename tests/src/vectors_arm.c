/* ARM Cortex-M vector table. Only compiled into ARM targets so that
 * anchor's arm_vectors strategy has something distinctive to detect
 * at offset 0 of the image. */

void nmi_handler(void) { while (1) { } }
void hf_handler(void)  { while (1) { } }

extern int _start(void);

__attribute__((section(".vectors"), used))
void * const vectors[16] = {
    (void*)0x20008000,     /* initial SP - plausible RAM address */
    (void*)_start,         /* reset handler (Thumb bit set by linker) */
    (void*)nmi_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
    (void*)hf_handler,
};
