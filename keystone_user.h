//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef _KEYSTONE_USER_H_
#define _KEYSTONE_USER_H_

#include <linux/types.h>
#include <linux/ioctl.h>
// Linux generic TEE subsystem magic defined in <linux/tee.h>
#define KEYSTONE_IOC_MAGIC  0xa4

// ioctl definition
#define KEYSTONE_IOC_CREATE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x00, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_DESTROY_ENCLAVE \
  _IOW(KEYSTONE_IOC_MAGIC, 0x01, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_RUN_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x04, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_RESUME_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x05, struct keystone_ioctl_run_enclave)
#define KEYSTONE_IOC_FINALIZE_ENCLAVE \
  _IOR(KEYSTONE_IOC_MAGIC, 0x06, struct keystone_ioctl_create_enclave)
#define KEYSTONE_IOC_UTM_INIT \
  _IOR(KEYSTONE_IOC_MAGIC, 0x07, struct keystone_ioctl_create_enclave)

#define RT_NOEXEC 0
#define USER_NOEXEC 1
#define RT_FULL 2
#define USER_FULL 3
#define UTM_FULL 4


#if __riscv_xlen == 64
typedef __u64 u_ptr;
#elif __riscv_xlen == 32
typedef __u32 u_ptr;
#endif 

struct runtime_params_t {
  u_ptr runtime_entry;
  u_ptr user_entry;
  u_ptr untrusted_ptr;
  u_ptr  untrusted_size;
};

struct keystone_ioctl_create_enclave {
  u_ptr eid;

  //Min pages required
  u_ptr min_pages;

  // virtual addresses
  u_ptr runtime_vaddr;
  u_ptr user_vaddr;

  u_ptr pt_ptr;
  u_ptr utm_free_ptr;

  //Used for hash
  u_ptr epm_paddr;
  u_ptr utm_paddr;
  u_ptr runtime_paddr;
  u_ptr user_paddr;
  u_ptr free_paddr;

  u_ptr epm_size;
  u_ptr utm_size;

  // Runtime Parameters
  struct runtime_params_t params;
};

struct keystone_ioctl_run_enclave {
  u_ptr eid;
  u_ptr entry;
  u_ptr args_ptr;
  u_ptr args_size;
  u_ptr ret;
};

#endif
