// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Linux Kernel Tracer API
 *
 * Author: Freysteinn Alfredsson <freysteinn.alfredsson@kau.se>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>
#include <linux/mutex.h>

#include "tracer.h"

struct lkl_tracer_node {
	pid_t pid;
	int kmalloc_count;
	int kfree_count;
	int kmalloc_mem;
	int kfree_mem;
	int sched_count;
	int up_count;
	int down_count;
	int lock_count;
	int unlock_count;

	struct rb_node node;
};

static int lkl_tracer_proc_show(struct seq_file *m, void *v);
static int lkl_tracer_read_open(struct inode *inode, struct file *file);
static int lkl_kmalloc_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int lkl_kfree_probe_handler(struct kprobe *p, struct pt_regs *regs);
static int lkl_tracer_insert(struct rb_root *root, struct lkl_tracer_node *data);
static struct lkl_tracer_node *lkl_tracer_search(struct rb_root *root, int pid);


static DEFINE_MUTEX(lkl_tracer_mutex);

struct proc_dir_entry *proc_tracer;

static struct rb_root lkl_tracer_root = RB_ROOT;

static struct kprobe lkl_kp_kfree = {
	.symbol_name = "kfree",
	.pre_handler = lkl_kfree_probe_handler,
};

static struct kretprobe lkl_krp_kmalloc = {
	.kp = {
		.symbol_name = "__kmalloc",
	},
	.handler = lkl_kmalloc_probe_handler,
};


static struct kprobe *lkl_tracer_probes[] = {
	&lkl_kp_kfree,
};

static struct kretprobe *lkl_tracer_retprobes[] = {
	&lkl_krp_kmalloc,
};

static int lkl_kmalloc_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct lkl_tracer_node *node;
	int pid = current->pid;


//	mutex_lock(&lkl_tracer_mutex);

	node = lkl_tracer_search(&lkl_tracer_root, pid);
	if (!node)
		goto out;

	node->kmalloc_count++;
	node->kmalloc_mem += regs_return_value(regs);

out:
//	mutex_unlock(&lkl_tracer_mutex);

	return 0;
}

static int lkl_kfree_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct lkl_tracer_node *node;
	int pid = current->pid;

//	mutex_lock(&lkl_tracer_mutex);

	node = lkl_tracer_search(&lkl_tracer_root, pid);
	if (!node)
		goto out;

	node->kfree_count++;
	node->kfree_mem += regs->di;

out:
//	mutex_unlock(&lkl_tracer_mutex);

	return 0;
}

static struct lkl_tracer_node *lkl_tracer_search(struct rb_root *root, int pid)
{
	struct rb_node *node = root->rb_node;
	struct lkl_tracer_node *data;

	while (node) {
		data = container_of(node, struct lkl_tracer_node, node);

		if (pid < data->pid)
			node = node->rb_left;
		else if (pid > data->pid)
			node = node->rb_right;
		else
			return data;
	}

	return NULL;
}


static int lkl_tracer_insert(struct rb_root *root, struct lkl_tracer_node *data)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;
	int ret = 0;

	while (*new) {
		struct lkl_tracer_node *this = container_of(*new, struct lkl_tracer_node, node);

		parent = *new;
		if (data->pid < this->pid) {
			new = &((*new)->rb_left);
		}
		else if (data->pid > this->pid) {
			new = &((*new)->rb_right);
		} else {
			ret = -EEXIST;
			goto out;
		}
	}

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
out:
	return ret;
}

static int lkl_tracer_get_digits(int number)
{
	int digits = 0;

	if (number == 0)
		return 1;

	while (number) {
		number /= 10;
		digits++;
	}

	return digits;
}

static struct lkl_tracer_node lkl_tracer_get_max_node(void)
{
	struct rb_node *node;
	struct lkl_tracer_node max_node;
	max_node.pid = strlen("PID");
	max_node.kmalloc_count = strlen("kmalloc");
	max_node.kfree_count = strlen("kfree");
	max_node.kmalloc_mem = strlen("kmalloc_mem");
	max_node.kfree_mem = strlen("kfree_mem");
	max_node.sched_count = strlen("sched");
	max_node.up_count = strlen("up");
	max_node.down_count = strlen("down");
	max_node.lock_count = strlen("lock");
	max_node.unlock_count = strlen("unlock");

	for (node = rb_first(&lkl_tracer_root); node; node = rb_next(node)) {
		struct lkl_tracer_node *data = container_of(node, struct lkl_tracer_node, node);
		max_node.pid = max(max_node.pid, lkl_tracer_get_digits(data->pid));
		max_node.kmalloc_count = max(max_node.kmalloc_count, lkl_tracer_get_digits(data->kmalloc_count));
		max_node.kfree_count = max(max_node.kfree_count, lkl_tracer_get_digits(data->kfree_count));
		max_node.kmalloc_mem = max(max_node.kmalloc_mem, lkl_tracer_get_digits(data->kmalloc_mem));
		max_node.kfree_mem = max(max_node.kfree_mem, lkl_tracer_get_digits(data->kfree_mem));
		max_node.sched_count = max(max_node.sched_count, lkl_tracer_get_digits(data->sched_count));
		max_node.up_count = max(max_node.up_count, lkl_tracer_get_digits(data->up_count));
		max_node.down_count = max(max_node.down_count, lkl_tracer_get_digits(data->down_count));
		max_node.lock_count = max(max_node.lock_count, lkl_tracer_get_digits(data->lock_count));
		max_node.unlock_count = max(max_node.unlock_count, lkl_tracer_get_digits(data->unlock_count));
	}

	return max_node;
}

static int lkl_tracer_proc_show(struct seq_file *m, void *v)
{
	struct lkl_tracer_node max_node = lkl_tracer_get_max_node();
	struct rb_node *node;

	seq_printf(m, "%*s ", max_node.pid, "PID");
	seq_printf(m, "%*s ", max_node.kmalloc_count, "kmalloc");
	seq_printf(m, "%*s ", max_node.kfree_count, "kfree");
	seq_printf(m, "%*s ", max_node.kmalloc_mem, "kmalloc_mem");
	seq_printf(m, "%*s ", max_node.kfree_mem, "kfree_mem");
	seq_printf(m, "%*s ", max_node.sched_count, "sched");
	seq_printf(m, "%*s ", max_node.up_count, "up");
	seq_printf(m, "%*s ", max_node.down_count, "down");
	seq_printf(m, "%*s ", max_node.lock_count, "lock");
	seq_printf(m, "%*s\n", max_node.unlock_count, "unlock");

	for (node = rb_first(&lkl_tracer_root); node; node = rb_next(node)) {
		struct lkl_tracer_node *data = container_of(node, struct lkl_tracer_node, node);
		seq_printf(m, "%*d ", max_node.pid, data->pid);
		seq_printf(m, "%*d ", max_node.kmalloc_count, data->kmalloc_count);
		seq_printf(m, "%*d ", max_node.kfree_count, data->kfree_count);
		seq_printf(m, "%*d ", max_node.kmalloc_mem, data->kmalloc_mem);
		seq_printf(m, "%*d ", max_node.kfree_mem, data->kfree_mem);
		seq_printf(m, "%*d ", max_node.sched_count, data->sched_count);
		seq_printf(m, "%*d ", max_node.up_count, data->up_count);
		seq_printf(m, "%*d ", max_node.down_count, data->down_count);
		seq_printf(m, "%*d ", max_node.lock_count, data->lock_count);
		seq_printf(m, "%*d\n", max_node.unlock_count, data->unlock_count);
	}

	return 0;
}


static int lkl_tracer_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, lkl_tracer_proc_show, NULL);
}


static const struct proc_ops tracer_pops = {
	.proc_open	= lkl_tracer_read_open,
	.proc_read	= seq_read,
	.proc_release	= single_release,
};


static long lkl_tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct lkl_tracer_node *node;
	struct lkl_tracer_node *data;
	void __user *argp = (void __user *)arg;
	pid_t pid = (pid_t) arg;
	int ret;

	mutex_lock(&lkl_tracer_mutex);

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		if (copy_from_user(&pid, argp, sizeof(pid))) {
			pr_err("copy_from_user failed (%d)!\n", __LINE__);
			ret = -EFAULT;
			goto out;
		}

		data = lkl_tracer_search(&lkl_tracer_root, pid);
		if (data) {
			pr_err("Process %d already traced!\n", pid);
			ret = -EEXIST;
			goto out;
		}

		node = kcalloc(1, sizeof(*node), GFP_KERNEL);
		if (!node) {
			pr_err("kcalloc failed!\n");
			ret = -ENOMEM;
			goto out;
		}

		node->pid = pid;
		ret = lkl_tracer_insert(&lkl_tracer_root, node);
		if (ret) {
			pr_err("tracer_insert failed!\n");
			kfree(node);
			goto out;
		}

		break;
	case TRACER_REMOVE_PROCESS:
		if (copy_from_user(&pid, argp, sizeof(pid))) {
			pr_err("copy_from_user failed! (%d)\n", __LINE__);
			ret = -EFAULT;
			goto out;
		}

		data = lkl_tracer_search(&lkl_tracer_root, pid);
		if (!data) {
			pr_err("Process %d not traced!\n", pid);
			ret = -ENOENT;
			goto out;
		}

		rb_erase(&data->node, &lkl_tracer_root);
		kfree(data);

		break;
	default:
		ret = -ENOTTY;
	}
out:
	mutex_unlock(&lkl_tracer_mutex);

	return 0;
}

static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = lkl_tracer_ioctl,
};

static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_NAME,
	.fops = &tracer_fops,
};

static int __init lkl_tracer_init(void)
{
	int error;

	error = misc_register(&tracer_dev);
	if (error) {
		pr_err("misc_register failed!\n");
		goto misc_cleanup;
	}

	proc_tracer = proc_create(TRACER_NAME, 0000, NULL, &tracer_pops);
	if (!proc_tracer) {
		pr_err("proc_create failed!\n");
		error = -ENOMEM;
		goto proc_tracer_cleanup;
	}

	error = register_kprobes(lkl_tracer_probes, ARRAY_SIZE(lkl_tracer_probes));
	if (error) {
		pr_err("register_kprobes failed!\n");
		goto kprobes_cleanup;
	}

	error = register_kretprobes(lkl_tracer_retprobes, ARRAY_SIZE(lkl_tracer_retprobes));
	if (error) {
		pr_err("register_kretprobes failed!\n");
		goto kretprobes_cleanup;
	}

	return 0;


kretprobes_cleanup:
	unregister_kprobes(lkl_tracer_probes, ARRAY_SIZE(lkl_tracer_probes));
kprobes_cleanup:
	proc_remove(proc_tracer);
proc_tracer_cleanup:
	misc_deregister(&tracer_dev);
misc_cleanup:
	return error;
}

static void __exit lkl_tracer_exit(void)
{
	struct lkl_tracer_node *node;
	struct lkl_tracer_node *tmp;

	unregister_kretprobes((struct kretprobe **) lkl_tracer_retprobes, ARRAY_SIZE(lkl_tracer_retprobes));
	unregister_kprobes((struct kprobe **) lkl_tracer_probes, ARRAY_SIZE(lkl_tracer_probes));
	proc_remove(proc_tracer);
	misc_deregister(&tracer_dev);


	rbtree_postorder_for_each_entry_safe(node, tmp, &lkl_tracer_root, node) {
		rb_erase(&node->node, &lkl_tracer_root);
		kfree(node);
		(void)tmp; // Suppress warning about unused variable
	}

}

module_init(lkl_tracer_init);
module_exit(lkl_tracer_exit);

MODULE_DESCRIPTION("Linux Kernel Tracer");
MODULE_AUTHOR("Freysteinn Alfredsson <freysteinn.alfredsson@kau.se>");
MODULE_LICENSE("GPL v2");
