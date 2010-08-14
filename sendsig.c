/*
 *
 * Module: sendsig
 * Description: A small hack to kill crazy RT process
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
#define MOD_DESC "Small ack to check a process' cpu usage and kill it if it is too high."

#define SIG_TO_SEND 9
#define MAX_CPU 60
#define WAIT_TIMEOUT 5
#define MAX_CHECK 6 // This means that if the process has an high cpu
                    // usage for 30 second, it will be killed

struct timer_list check_timer;
struct dentry *file;
pid_t pid;
cputime_t last_cputime;
int count_check;

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


int process_cpu_usage(struct task_struct *task) 
{
  struct task_cputime times;
  cputime_t num_load, div_load, load, total_time;

  my_thread_group_cputime(task, &times);  
  total_time = cputime_add(times.utime, times.stime);
  /*
    if sum < last_cputime, the cpu usage is decreasing, so the process
    should be in a good state; while last_cputime == 0 means that the
    timer_function has been called for the first time and we have to
    collect info before doing any check.
  */
  if (total_time < last_cputime || last_cputime == 0) {
    printk("sendsig: module fully initialized\n");
    load = 1;
  } else {
    /*
      Let's compute the cpu usage of the last 5 seconds
    */
    num_load = cputime_sub(total_time, last_cputime) * 100;
    div_load = jiffies_to_cputime(WAIT_TIMEOUT*HZ);
    load = cputime_div(num_load, div_load);
    
    printk("sendsig: computed cpu load: %lu\n", load);
  }
  /*
    Update last_cputime
  */
  last_cputime = total_time;

  return (int)load;
}


int check_process(void) 
{
  struct siginfo info;
  struct task_struct *task;
  struct pid *struct_pid = NULL;
  
  memset(&info, 0, sizeof(struct siginfo));
  info.si_signo = SIG_TO_SEND;
  info.si_code = SI_KERNEL;

  rcu_read_lock();

  struct_pid = find_get_pid(pid);
  task = pid_task(struct_pid, PIDTYPE_PID);
  put_pid(struct_pid);

  if(task == NULL){
    printk("no such pid\n");
    rcu_read_unlock();
    return -ENODEV;
  }

  rcu_read_unlock();

  if (process_cpu_usage(task) >= MAX_CPU ) {
    count_check++;
    printk("sendsig: current cpu usage over limit of %i (check #%i)\n", MAX_CPU, count_check);
    
    if (count_check >= MAX_CHECK) {
      /*
	send the signal to the process
      */
      send_sig_info(SIG_TO_SEND, &info, task);
      count_check = 0;
      last_cputime = 0;
      printk("sendsig: sent signal to process %i\n", pid);
    } 
  } else {
    /*
      if the process is being good, let's reset its counter
    */
      count_check = 0;
  }

  return 1;
}


static void timer_function(unsigned long par)
{ 
  mod_timer(&check_timer, jiffies + WAIT_TIMEOUT*HZ); 
  check_process();

  return;
}


static ssize_t write_pid(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
  char mybuf[10];

  if(count > 10)
    return -EINVAL;

  copy_from_user(mybuf, buf, count);
  sscanf(mybuf, "%d", &pid);

  printk("sendsig: got pid = %d. I'll check it every %i seconds, after initialization\n", 
	 pid, WAIT_TIMEOUT);

  /* 
     let's see if a timer already exists. 
  */
  if (check_timer.expires)
    del_timer(&check_timer); // ... delete it 

  /* 
     install the new timer
  */
  init_timer(&check_timer);
  check_timer.function = timer_function;
  check_timer.expires = jiffies + WAIT_TIMEOUT*HZ;
  add_timer(&check_timer);

  /*
    update to zero the value of the last cputime usage
  */
  last_cputime = 0;
  /*
    update to zero the value of the check counter
  */
  count_check = 0;
  	
  return count;
}

static const struct file_operations my_fops = {
  .write = write_pid,
};

static int __init sendsig_module_init(void)
{
  file = debugfs_create_file("sendsig", 0200, NULL, NULL, &my_fops);
  printk("Module sendsig loaded\n");

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
