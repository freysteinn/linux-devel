// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Freysteinn Alfredsson <freysteinn.alfredsson@kau.se>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

static int list_add_top_of_list(char *name);
static int list_add_end_of_list(char *name);
static int list_del_first_from_list(char *name);
static int list_del_all_from_list(char *name);

struct lks_list_cmd {
	char *cmd;
	int (*cmd_function)(char *name);
};

struct lks_list_cmd lks_list_cmds[] = {
	{ "addf", list_add_top_of_list },
	{ "adde", list_add_end_of_list },
	{ "delf", list_del_first_from_list },
	{ "dela", list_del_all_from_list },
	{ NULL, NULL },
};

struct lks_node {
	char *name;
	struct list_head list;
};

static LIST_HEAD(lks_list);

static int list_proc_show(struct seq_file *m, void *v)
{
	struct lks_node *node;

	list_for_each_entry(node, &lks_list, list) {
		seq_printf(m, "%s\n", node->name);
	}
	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static struct lks_node *init_node(char *name)
{
	struct lks_node *node;

	node = kmalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return NULL;

	node->name = kasprintf(GFP_KERNEL, "%s", name);
	if (!node->name)
		return NULL;

	INIT_LIST_HEAD(&node->list);
	return node;
}

static int list_add_top_of_list(char *name)
{
	struct lks_node *new_node = init_node(name);

	if (!new_node)
		return -ENOMEM;

	list_add(&new_node->list, &lks_list);
	pr_info("Added '%s' to the top of the list", name);
	return 0;
}

static int list_add_end_of_list(char *name)
{
	struct lks_node *new_node = init_node(name);

	if (!new_node)
		return -ENOMEM;

	pr_info("Added '%s' to the end of the list", name);
	list_add_tail(&new_node->list, &lks_list);
	return 0;
}

static int list_del_first_from_list(char *name)
{
	struct lks_node *node;
	int found = 0;

	list_for_each_entry(node, &lks_list, list) {
		if (strcmp(node->name, name) == 0) {
			list_del(&node->list);
			kfree(node->name);
			kfree(node);
			found = 1;
			break;
		}
	}
	if (found)
		pr_info("Deleted '%s' from the list", name);
	return 0;
}

static int list_del_all_from_list(char *name)
{
	struct lks_node *node;
	struct lks_node *tmp;
	int found_count = 0;

	list_for_each_entry_safe(node, tmp, &lks_list, list) {
		if (strcmp(node->name, name) == 0) {
			list_del(&node->list);
			kfree(node->name);
			kfree(node);
			found_count++;
		}
	}
	if (found_count)
		pr_info("Deleted '%d' occurrences of %s from the list",
			found_count, name);
	return 0;
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char *local_buffer = (char *)get_zeroed_page(GFP_KERNEL);
	char *local_buffer_sep = local_buffer;
	unsigned long local_buffer_size = 0;
	char *cmd;
	char *name;
	struct lks_list_cmd *lks_list_cmd = lks_list_cmds;
	int ret = 0;

	if (!local_buffer) {
		ret = -ENOMEM;
		goto error1;
	}

	local_buffer_size = count;
	if (local_buffer_size >= PAGE_SIZE)
		local_buffer_size = PAGE_SIZE - 1;

	if (copy_from_user(local_buffer, buffer, local_buffer_size)) {
		ret = -EFAULT;
		goto error2;
	}

	cmd = strsep(&local_buffer_sep, " ");

	for (lks_list_cmd = lks_list_cmds; lks_list_cmd->cmd; lks_list_cmd++) {
		if (strcmp(lks_list_cmd->cmd, cmd) == 0)
			break;
	}
	if (!lks_list_cmd->cmd) {
		pr_warn("Unknown command: %s", cmd);
		ret = -EINVAL;
		goto error2;
	}

	while ((name = strsep(&local_buffer_sep, " ")) != NULL) {
		if (name[0] == '\0')
			continue;
		if (name[strlen(name) - 1] == '\n')
			name[strlen(name) - 1] = '\0';
		ret = lks_list_cmd->cmd_function(name);
		if (ret)
			goto error2;
	}
	ret = local_buffer_size;

error2:
	free_page((unsigned long)local_buffer);
error1:
	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int __init list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void __exit list_exit(void)
{
	struct lks_node *node;
	struct lks_node *tmp;

	list_for_each_entry_safe(node, tmp, &lks_list, list) {
		list_del(&node->list);
		kfree(node->name);
		kfree(node);
	}
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Freysteinn Alfredsson <freysteinn.alfredsson@kau.se>");
MODULE_LICENSE("GPL v2");
