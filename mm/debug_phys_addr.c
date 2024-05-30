// SPDX-License-Identifier: GPL-2.0-or-later

#include "linux/gfp_types.h"
#include "slab.h"
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/io.h>
#include <linux/kallsyms.h>
#include <linux/vmalloc.h>

#define INITIAL_BUFFER_SIZE PAGE_SIZE
#define EXPANSION_FACTOR 2
#define TEMP_BUFFER_SIZE 1024

#define DATA_HEADER \
	"Mem Space,Physical Addr,Virtual Addr,pid/symbol/vmlinux segment,task name\n"
#define READ_CHUNK_SIZE 512

static char *buffer;
static size_t buffer_size = INITIAL_BUFFER_SIZE;
static size_t data_size;
static int user_address_count;

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

static struct folio *get_folio(unsigned long pfn)
{
	struct page *page = pfn_to_online_page(pfn);
	struct folio *folio;

	if (!page || PageTail(page))
		return NULL;
	folio = page_folio(page);
	if (!folio_test_lru(folio) || !folio_try_get(folio))
		return NULL;
	if (unlikely(page_folio(page) != folio || !folio_test_lru(folio))) {
		folio_put(folio);
		folio = NULL;
	}
	return folio;
}

static bool folio_data(struct folio *folio, struct vm_area_struct *vma,
		       unsigned long v_address, void *arg)
{
	struct task_struct *task = vma->vm_mm->owner;
	unsigned long long addr_to_resolve = *(unsigned long long *)arg;
	unsigned int offset_within_page = offset_in_page(addr_to_resolve);

	dynamic_buffer_write("Process,0x%llx,0x%lx,%d,%s\n", addr_to_resolve,
			     v_address + offset_within_page, task->pid,
			     task->comm);
	user_address_count++;
	return true;
}

static bool analyse_kmalloc_memory(char *temp_buf, const phys_addr_t addr)
{
	unsigned long caller;
	const char *sym_ret;
	unsigned long symbolsize;
	unsigned long offset;
	char *modname;
	char *namebuf = temp_buf;
	void *object = phys_to_virt(addr);
	struct slab *slab;
	struct kmem_cache *s;
	struct folio *folio;
	struct page *page = pfn_to_online_page(PHYS_PFN(addr));

	if (!page || PageTail(page))
		return false;
	folio = page_folio(page);

	if (!folio)
		return false;
	if (!folio_test_slab(folio))
		return false;

	slab = folio_slab(folio);
	if (!slab)
		return false;
	s = slab->slab_cache;
	object = nearest_obj(s, slab, object);
	caller = get_track_alloc(s, object);
	sym_ret = kallsyms_lookup(caller, &symbolsize, &offset, &modname,
				  namebuf);
	if (sym_ret) {
		dynamic_buffer_write(
			"kmalloc,0x%llx,0x%llx,%s+0x%lx/0x%lx,%s\n", addr,
			(unsigned long long)object, namebuf, offset, symbolsize,
			modname ? modname : "kernel");
		return true;
	}
	return false;
}

static bool analyse_kernel_symbols(char *temp_buf,
				   const unsigned long long paddr)
{
	unsigned long symbolsize;
	unsigned long offset;
	char *modname;
	char *namebuf = temp_buf;
	const char *ret;
	unsigned long long addr = (unsigned long long)__va_symbol(paddr);

	ret = kallsyms_lookup(addr, &symbolsize, &offset, &modname, namebuf);
	if (ret) {
		dynamic_buffer_write(
			"kernel symbol,0x%llx,0x%llx,%s+0x%lx/0x%lx,%s\n",
			paddr, addr, namebuf, offset, symbolsize,
			modname ? modname : "kernel");
		return true;
	}
	return false;
}

static bool analyse_vmalloc_memory(const phys_addr_t phys_addr)
{
	struct vmap_area *va = get_vmap_area(phys_addr);

	if (!va)
		return false;
	dynamic_buffer_write("vmalloc,0x%llx,0x%lx,%pS,kernel\n", phys_addr,
			     va->va_start,
			     va->vm->caller ? va->vm->caller : "NA");
	return true;
}

static void analyse_physical_address(char *temp_buf,
				     const unsigned long long addr)
{
	unsigned long long data = addr;
	struct folio *folio = get_folio(PHYS_PFN(addr));
	struct rmap_walk_control rwc = {
		.rmap_one = folio_data,
		.arg = (void *)&data,
	};

	if (folio != NULL)
		rmap_walk(folio, &rwc);

	if (user_address_count > 0) {
		user_address_count = 0;
		return;
	}

	if (analyse_kmalloc_memory(temp_buf, addr))
		return;
	if (analyse_kernel_symbols(temp_buf, addr))
		return;
	if (analyse_vmalloc_memory(addr))
		return;
	/* Insert Blank Entry */
	dynamic_buffer_write("NA,0x%llx,,,,\n", addr);
}

static ssize_t debug_phys_addr_write(struct file *filp, const char __user *buf,
				     size_t count, loff_t *f_pos)
{
	char *temp_buf;
	int ret = count;
	unsigned long long addr;

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
	if (kstrtoull(temp_buf, 16, &addr)) {
		pr_warn("invalid address '%s'\n", temp_buf);
		ret = -EFAULT;
		goto exit;
	}
	analyse_physical_address(temp_buf, addr);
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
