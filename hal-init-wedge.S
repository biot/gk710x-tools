.syntax unified
.arm
.text
.global _start

HAL_INIT_TAIL   = 0xc001213c
LOG_START       = 0x82800000
LOG_END         = 0x83800000
HW_OPS_ENTRIES  = 18


// load at 0xc0016000
install_init_wedge:
    push { r3, r4, lr }
    ldr r4, =HAL_INIT_TAIL
    ldr r3, =#0xea000fb5    @ b post_init_wedge
    str r3, [r4]
    mov r0, #0xa5
    pop { r3, r4, pc }

post_init_wedge:
    push { r3, r4, r5, r6, r7, r8 }
    mov r8, #0
    ldr r3, =#0xc0015ad0
    adr r4, hal_call_start
    adr r5, orig_funcptrs
overwrite_calls:
    ldr r7, [r3, r8]
    str r7, [r5, r8]
    str r4, [r3, r8]
    add r8, r8, #0x04
    add r4, r4, #0x0c
    cmp r8, #(4 * HW_OPS_ENTRIES)
    blt overwrite_calls
    pop { r3, r4, r5, r6, r7, r8 }

    /* restore old hal_init() ending, so it can be called again */
    ldr r3, =#0xe8bd85f8
    ldr r4, =HAL_INIT_TAIL
//    str r3, [r4]

    /* return to hal_init() */
    pop { r3, r4, r5, r6, r7, r8, r10, pc }

orig_funcptrs:
.rept HW_OPS_ENTRIES
.long 0x55555555
.endr

hal_call_start:
.rept HW_OPS_ENTRIES
    stmdb sp!, { r4, r5, r6, r7 }
    /* calculate call id */
    mov r4, (. - 4 - hal_call_start) / 12
    b log_call
.endr
log_call:
    ldr r6, log_ptr
    cmp r6, #(LOG_END - LOG_START)
    bge log_done
    ldr r5, log_start
    add r5, r5, r6
    /* in decompression stage at 0xc1xxxxxxxx? */
    mov r7, #0xc1
    cmp r7, lr, lsr #24
    orreq r5, r5, #0x40000000		/* yes, RAM is at 0xc0000000 */
    bicne r5, r5, #0x40000000		/* no, RAM is at 0x80000000 */
    /* filter out duplicates */
    sub r5, r5, #0x10
    ldr r7, [r5]
    cmp lr, r7
    bne unique
    ldr r7, [r5, #4]
    cmp r4, r7
    bne unique
    ldr r7, [r5, #8]
    cmp r0, r7
    bne unique
    ldr r7, [r5, #12]
    cmp r1, r7
    beq log_done
unique:
    add r5, r5, #0x10
    str lr, [r5]
    str r4, [r5, #4]
    str r0, [r5, #8]
    str r1, [r5, #0x0c]
    add r6, r6, #0x10
    str r6, log_ptr
log_done:
    adr r5, orig_funcptrs
    add r5, r5, r4, lsl #2
    ldr r5, [r5]
    str r5, orig_func
    ldmia sp!, { r4, r5, r6, r7 }
    ldr pc, orig_func
log_ptr:
.long 0
orig_func:
.long 0
log_start:
.long LOG_START
