#ifndef LWIP_ARCH_SYS_ARCH_H
#define LWIP_ARCH_SYS_ARCH_H

#define SYS_MBOX_NULL   NULL
#define SYS_SEM_NULL    NULL
#define LWIP_NO_UNISTD_H 1

int sys_arch_pcb_watch(void* pcb);
int sys_arch_pcb_is_watch(void* pcb);
int sys_arch_pcb_unwatch(void* pcb);
#endif /* LWIP_ARCH_SYS_ARCH_H */