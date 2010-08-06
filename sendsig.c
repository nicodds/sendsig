#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/siginfo.h>	//siginfo
#include <linux/rcupdate.h>	//rcu_read_lock
#include <linux/sched.h>	//find_task_by_pid_type
#include <linux/pid.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/timer.h>
#include <linux/posix-timers.h>
#include <linux/kernel_stat.h>
#include <asm/cputime.h>

#define SIG_TO_SEND 9
#define WAIT_TIMEOUT 5
#define MAX_CPU 85

extern struct sighand_struct *lock_task_sighand(struct task_struct *tsk,
						unsigned long *flags);

struct timer_list check_timer;
struct dentry *file;
pid_t pid;


int process_cpu_usage(struct task_struct *task) {
  struct task_cputime cputime;
  cputime_t utime = 0;
  cputime_t stime = 0;
  unsigned long flags;

  if (lock_task_sighand(task, &flags)) {
    thread_group_cputime(task, &cputime);
    utime = cputime.utime;
    stime = cputime.stime;
    unlock_task_sighand(task, &flags);
  }

  printk("cputime: %lu (u), %lu (s)\n", utime, stime);

  return 1;
}


int check_process(void) {
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

  //  return send_sig_info(SIG_TO_SEND, &info, task);    //send the signal
  return process_cpu_usage(task);

}


static void timer_function(unsigned long par)
{ 
  mod_timer(&check_timer, jiffies + WAIT_TIMEOUT*HZ); /* jiffies is the current time. Timer 
				     expires after par*HZ clock ticks, that is, after par seconds */
  check_process();

  return;
}


static ssize_t write_pid(struct file *file, const char __user *buf,
			 size_t count, loff_t *ppos)
{
  char mybuf[10];

  /* read the value from user space */
  if(count > 10)
    return -EINVAL;
  copy_from_user(mybuf, buf, count);
  sscanf(mybuf, "%d", &pid);
  printk("pid = %d\n", pid);

  /* send the signal */

  if (check_timer.expires)
    del_timer(&check_timer);

  init_timer(&check_timer);
  check_timer.function = timer_function;
  check_timer.expires = jiffies + WAIT_TIMEOUT*HZ;
  add_timer(&check_timer);
  	
  return count;
}

static const struct file_operations my_fops = {
  .write = write_pid,
};

static int __init signalexample_module_init(void)
{
  /* we need to know the pid of the user space process
   * -> we use debugfs for this. As soon as a pid is written to 
   * this file, a signal is sent to that pid
   */

  /* only root can write to this file (no read) */
  file = debugfs_create_file("signalconfpid", 0200, NULL, NULL, &my_fops);
  printk("Trying to inizialize module...\n");
  return 0;
}
static void __exit signalexample_module_exit(void)
{
  printk("Unloading module...\n");
  del_timer(&check_timer);
  debugfs_remove(file);

}

module_init(signalexample_module_init);
module_exit(signalexample_module_exit);

MODULE_LICENSE("GPL");
