#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/pid.h>




extern struct task_struct *find_task_by_vpid(pid_t nr);

