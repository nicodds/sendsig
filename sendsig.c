/*
 *
 * Module: sendsig
 * Description: A small hack to kill crazy real time processes
 *
 * Copyright 2010, Alca Società Cooperativa
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/siginfo.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <asm/cputime.h>

#define MOD_AUTHOR "Domenico Delle Side <domenico.delleside@alcacoop.it>"
#define MOD_DESC "Small kernel module to check a process' cpu usage and kill it if too high"

/* safe defaults for the module params */
#define SIG_TO_SEND 9
#define MAX_CPU_SHARE 90
#define WAIT_TIMEOUT 10
#define MAX_CHECKS 6 

static int sig_to_send = SIG_TO_SEND;
static ushort max_cpu_share = MAX_CPU_SHARE;
static ushort wait_timeout = WAIT_TIMEOUT;
static ushort max_checks = MAX_CHECKS;

module_param(sig_to_send, int, 0000);
MODULE_PARM_DESC(sig_to_send, " The signal code you want to send (default: SIGKILL, 9)");
module_param(max_cpu_share, ushort, 0000);
MODULE_PARM_DESC(max_cpu_share, " The maximum cpu share admissible for the process, a value between 0 and 100 (default: 90)");
module_param(wait_timeout, ushort, 0000);
MODULE_PARM_DESC(wait_timeout, " The number of seconds to wait between each check (default: 10)");
module_param(max_checks, ushort, 0000);
MODULE_PARM_DESC(max_checks, " The number of checks after which the signal is sent (default: 6)");


struct timer_list check_timer;
struct task_struct *check_task;
struct dentry *file;
pid_t pid;
cputime_t last_cputime;
ushort count_check;

/* 
   This function is not exported to modules by the kernel, so let's
   re-define it there. Taken from
   LINUX_SOURCE/kernel/posix-cpu-timers.c. Kudos to its author.
*/

void my_thread_group_cputime(struct task_struct *tsk, struct task_cputime *times)
{
	struct sighand_struct *sighand;
	struct signal_struct *sig;
	struct task_struct *t;

	*times = INIT_CPUTIME;

	rcu_read_lock();
	sighand = rcu_dereference(tsk->sighand);
	if (!sighand)
		goto out;

	sig = tsk->signal;

	t = tsk;
	do {
		times->utime = cputime_add(times->utime, t->utime);
		times->stime = cputime_add(times->stime, t->stime);
		times->sum_exec_runtime += t->se.sum_exec_runtime;

		t = next_thread(t);
	} while (t != tsk);

	times->utime = cputime_add(times->utime, sig->utime);
	times->stime = cputime_add(times->stime, sig->stime);
	times->sum_exec_runtime += sig->sum_sched_runtime;
out:
	rcu_read_unlock();
}


static ushort thread_group_cpu_share(struct task_struct *task) 
{
  struct task_cputime times;
  cputime_t num_load, div_load, total_time;
  ushort share;

  my_thread_group_cputime(task, &times);  
  total_time = cputime_add(times.utime, times.stime);
  /*
    last_cputime == 0 means that the timer_function has been called
    for the first time and we have to collect info before doing any
    check.
  */
  if (unlikely(last_cputime == 0)) {
    share = 0;
    printk(KERN_INFO "sendsig: timer initialization completed\n");
  } else {
    /*
      Let's compute the share of cpu usage for the last WAIT_TIMEOUT
      seconds
    */
    num_load = cputime_sub(total_time, last_cputime) * 100;
    div_load = jiffies_to_cputime(wait_timeout * HZ);
    share = (ushort)cputime_div(num_load, div_load);
    
    printk(KERN_DEBUG "sendsig: computed cpu share for process %d: %d\n", 
	   pid, share);
  }
  /*
    Update last_cputime
  */
  last_cputime = total_time;

  return share;
}


static struct task_struct *get_check_task(pid_t pid) 
{
  struct task_struct *task;
  struct pid *struct_pid = NULL;
  
  rcu_read_lock();

  struct_pid = find_get_pid(pid);
  task = pid_task(struct_pid, PIDTYPE_PID);
  //put_pid(struct_pid);

  rcu_read_unlock();

  if(unlikely(task == NULL)){
    printk(KERN_INFO "sendsig: no process with pid %d found\n", pid);
    return NULL;
  }

  return task;
}


static void timer_function(unsigned long par)
{ 
  struct siginfo info;
  ushort cpu_share = thread_group_cpu_share(check_task);

  if ( cpu_share >= max_cpu_share ) {
    count_check++;
    printk(KERN_INFO "sendsig: current cpu share over limit of %i (check #%i)\n", 
	   max_cpu_share, count_check);

/* the ratio is: if the process has a cpu share higher than
   max_cpu_share for more than max_checks * wait_timeout seconds, then
   we'll send the signal sig_to_send to it
 */    
    if (count_check >= max_checks) {
      /*
	initialize the signal structure
      */
      memset(&info, 0, sizeof(struct siginfo));
      info.si_signo = sig_to_send;
      info.si_code = SI_KERNEL;
      /*
	send the signal to the process
      */
      send_sig_info(sig_to_send, &info, check_task);
      /*
	remove the timer
       */
      del_timer(&check_timer);
      printk(KERN_INFO "sendsig: sent signal to process %i, timer removed\n", pid);
      return;
    } 
  } else {
    /*
      if the process is being good, let's reset its counter
    */
    count_check = 0;
  }  
  /*
    update the timer
  */
  mod_timer(&check_timer, jiffies + wait_timeout * HZ); 

  return;
}


static ssize_t write_pid(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
  char mybuf[10];

  if(unlikely(count > 10))
    return -EINVAL;

  copy_from_user(mybuf, buf, count);
  sscanf(mybuf, "%d", &pid);

  printk(KERN_INFO "sendsig: got pid = %d. Checking it every %i seconds, after timer initialization\n", 
	 pid, wait_timeout);
  /*
     get the task struct to check
  */
  check_task = get_check_task(pid);

  if (unlikely(check_task == NULL)) {
    printk(KERN_INFO "sendsig: can't check non-existent process, exiting\n");
    return -ENODEV;
  }
  /*
    update to zero the value of the last cputime usage
  */
  last_cputime = 0;
  /*
    update to zero the value of the check counter
  */
  count_check = 0;
  /* 
     let's see if a timer already exists. 
  */
  if (unlikely(check_timer.expires))
    del_timer(&check_timer); /*... delete it */
  /* 
     install the new timer
  */
  init_timer(&check_timer);
  check_timer.function = timer_function;
  check_timer.expires = jiffies + wait_timeout*HZ;
  add_timer(&check_timer);
  	
  return count;
}

static const struct file_operations sendsig_fops = {
  .write = write_pid,
};

static int __init sendsig_module_init(void)
{
  file = debugfs_create_file("sendsig", 0200, NULL, NULL, &sendsig_fops);
  printk(KERN_INFO "Module sendsig loaded\n");

  return 0;
}


static void __exit sendsig_module_exit(void)
{
  del_timer(&check_timer);
  debugfs_remove(file);
  printk("Module sendsig unloaded\n");
}


module_init(sendsig_module_init);
module_exit(sendsig_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
