// SPDX-License-Identifier: GPL-2.0-or-later

#include "linux/gfp_types.h"
#include <linux/debugfs.h>
#include <linux/string.h>

#define INITIAL_BUFFER_SIZE PAGE_SIZE
#define EXPANSION_FACTOR 2
#define TEMP_BUFFER_SIZE 256

#define DATA_HEADER \
	"Mem Space,Physical Addr,Virtual Addr,pid/symbol/vmlinux segment,task name\n"
#define READ_CHUNK_SIZE 512

static char *buffer;
static size_t buffer_size = INITIAL_BUFFER_SIZE;
static size_t data_size;

static int __init debug_phys_addr_init(void);

static ssize_t dynamic_buffer_write(const char *fmt, ...)
{
	size_t required_size;
	size_t new_buffer_size;
	char *new_buffer;
	va_list args;
	int len;

	va_start(args, fmt);
	len = vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	if (len < 0) {
		pr_err("Failed to get string length\n");
		return -EINVAL;
	}
	/* Accounting the NULL termination */
	len++;
	required_size = data_size + len;
	if (required_size > buffer_size) {
		/* Expand the buffer */
		new_buffer_size = buffer_size * EXPANSION_FACTOR;
		while (required_size > new_buffer_size)
			new_buffer_size *= EXPANSION_FACTOR;

		new_buffer = krealloc(buffer, new_buffer_size, GFP_KERNEL);
		if (!new_buffer) {
			pr_err("Failed to reallocate memory for dynamic buffer\n");
			return -ENOMEM;
		}
		buffer = new_buffer;
		buffer_size = new_buffer_size;
	}

	/* Write data to the buffer */
	va_start(args, fmt);
	vsnprintf(buffer + data_size, len, fmt, args);
	va_end(args);
	data_size += len;

	return len;
}

static int reset_buffer(void)
{
	char *new_buffer;

	data_size = 0;
	new_buffer = krealloc(buffer, INITIAL_BUFFER_SIZE, GFP_KERNEL);
	if (!new_buffer) {
		pr_err("Failed to reallocate memory for dynamic buffer\n");
		return -ENOMEM;
	}
	buffer = new_buffer;
	dynamic_buffer_write(DATA_HEADER);
	data_size = strlen(DATA_HEADER);
	return 0;
}

static ssize_t debug_phys_addr_write(struct file *filp, const char __user *buf,
				     size_t count, loff_t *f_pos)
{
	char *temp_buf;
	int ret = count;

	count = min(count, TEMP_BUFFER_SIZE - 1);
	temp_buf = kmalloc(TEMP_BUFFER_SIZE, GFP_KERNEL);

	if (copy_from_user(temp_buf, buf, count)) {
		ret = -EFAULT;
		goto exit;
	}
	temp_buf[count] = '\0';

	if (count == 1 && temp_buf[0] == 0x0A) {
		reset_buffer();
		goto exit;
	}
exit:
	kfree(temp_buf);
	return ret;
}

static ssize_t debug_phys_addr_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	size_t bytes_to_read;
	loff_t read_offset = *ppos;

	if (read_offset >= data_size)
		return 0;

	bytes_to_read = min(count, data_size - read_offset);
	bytes_to_read = min(bytes_to_read, READ_CHUNK_SIZE);

	if (copy_to_user(buf, buffer + read_offset, bytes_to_read)) {
		pr_err("Failed to copy data to user space\n");
		return -EFAULT;
	}
	*ppos += bytes_to_read;
	return bytes_to_read;
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
	return reset_buffer();
}
device_initcall(debug_phys_addr_init);
