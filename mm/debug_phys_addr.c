// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/debugfs.h>

static int __init debug_phys_addr_init(void);

static ssize_t debug_phys_addr_write(struct file *filp, const char __user *buf,
				     size_t count, loff_t *f_pos)
{
	return count;
}

static ssize_t debug_phys_addr_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	return 0;
}

static int debug_phys_addr_open(struct inode *inode, struct file *filp)
{
	return 0; /* success */
}

static int debug_phys_addr_release(struct inode *inode, struct file *filp)
{
	return 0; /* success */
}

const struct file_operations debug_phys_addr_proc_ops = {
	.read = debug_phys_addr_read,
	.write = debug_phys_addr_write,
	.open = debug_phys_addr_open,
	.release = debug_phys_addr_release,
};

static int __init debug_phys_addr_init(void)
{
	debugfs_create_file("debug_phys_addr", 0600, NULL, NULL,
			    &debug_phys_addr_proc_ops);
	return 0;
}
device_initcall(debug_phys_addr_init);
