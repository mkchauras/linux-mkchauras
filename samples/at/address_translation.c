#include "asm-generic/sections.h"
#include "asm/page.h"
#include "linux/ioport.h"
#include "linux/kallsyms.h"
#include "linux/list.h"
#include "linux/mm_types.h"
#include "linux/pfn.h"
#include "linux/printk.h"
#include "linux/sched.h"
#include "linux/vmalloc.h"
#include "../mm/slab.h"
#include <asm-generic/errno-base.h>
#include <asm/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/rmap.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/debugfs.h>

void reset_buffer(void);
ssize_t dynamic_buffer_write(const char *fmt, ...);
void __exit at_exit(void);
int __init at_init(void);

struct slab *get_slab(void *p);
#define DEBUGFS_DIR_NAME "at"
#define DEBUGFS_FILE_NAME "at"

extern struct resource iomem_resource;

static struct dentry *debugfs_dir;
static struct dentry *debugfs_file;

extern struct list_head vmap_area_list;

struct task_data {
	struct task_struct *task;
	struct vm_area_struct *vma;
} task_data;

struct rwc_args {
	unsigned long long addr_to_be_resolved;
	int count;
};

struct addr_range {
	char *name;
	void *start;
	void *end;
};

#define SEGMENT_CODE 0
#define SEGMENT_RODATA 1
#define SEGMENT_DATA 2
#define SEGMENT_BSS 3

#define NR_SEGMENTS 4

struct kernel_segments {
	struct addr_range seg[NR_SEGMENTS];
} ksegm;

#define INITIAL_BUFFER_SIZE PAGE_SIZE
#define EXPANSION_FACTOR 2
#define CHUNK_SIZE 512
#define DATA_HEADER \
	"Mem Space,Physical Addr,Virtual Addr,pid/symbol/vmlinux segment,task name\n"
#define DATA_HEADER_LEN 75

static char *buffer;
static size_t buffer_size = INITIAL_BUFFER_SIZE;
static size_t data_size = 0;

#define TEMP_BUFFER_SIZE 128
static char *temp_buffer;

static int user_address_count = 0;
ssize_t dynamic_buffer_write(const char *fmt, ...)
{
	size_t required_size;
	size_t new_buffer_size;
	char *new_buffer;
	va_list args;
	int len;

	// Calculate the length of the formatted string
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
		while (required_size > new_buffer_size) {
			new_buffer_size *= EXPANSION_FACTOR;
		}
		new_buffer = krealloc(buffer, new_buffer_size * sizeof(char),
				      GFP_KERNEL);
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

struct slab *get_slab(void *p)
{
	struct folio *folio;
	struct slab *slab;

	if (!p)
		return NULL;

	folio = virt_to_folio(p);
	slab = folio_slab(folio);
	return slab;
}

void reset_buffer(void)
{
	strncpy(buffer, DATA_HEADER, DATA_HEADER_LEN);
	data_size = DATA_HEADER_LEN;
}

/*
 * Code copied from Linux Kernel Source
 * Idle page tracking only considers user memory pages, for other types of
 * pages the idle flag is always unset and an attempt to set it is silently
 * ignored.
 *
 * We treat a page as a user memory page if it is on an LRU list, because it is
 * always safe to pass such a page to rmap_walk(), which is essential for idle
 * page tracking. With such an indicator of user pages we can skip isolated
 * pages, but since there are not usually many of them, it will hardly affect
 * the overall result.
 *
 * This function tries to get a user memory page by pfn as described above.
 */
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
/*
 * TODO Handle Compound Page
 */
static unsigned long long get_physical_address(unsigned long virt_addr,
					       struct task_struct *task)
{
	struct mm_struct *task_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	struct page *page = NULL;
	unsigned long offset_within_page;
	unsigned long long phys_addr = 0;

	task_mm = task->mm;
	// acquire page table lock
	spin_lock(&(task_mm->page_table_lock));

	pgd = pgd_offset(task_mm, virt_addr);
	if (pgd_none(*pgd))
		pr_emerg("No pgd");

	p4d = p4d_offset(pgd, virt_addr);
	if (p4d_none(*p4d))
		pr_emerg("No p4d");

	pud = pud_offset(p4d, virt_addr);
	if (pud_none(*pud))
		pr_emerg("No pud");

	pmd = pmd_offset(pud, virt_addr);
	if (pmd_none(*pmd))
		pr_emerg("No pmd");

	pte = pte_offset_kernel(pmd, virt_addr);
	if (pte_present(*pte)) {
		page = pte_page(*pte);
		offset_within_page = (virt_addr) & (PAGE_SIZE - 1);
		phys_addr = page_to_phys(page) + offset_within_page;
	}
	pte_unmap(pte);

done:
	// Release spin lock
	spin_unlock(&(task_mm->page_table_lock));
	return phys_addr;
}

static void store_kernel_address_range(struct resource *sys_ram)
{
	struct resource *iter = sys_ram;
	while (iter) {
		if (!strncmp("Kernel code", iter->name, 11)) {
			ksegm.seg[SEGMENT_CODE].start = _stext;
			ksegm.seg[SEGMENT_CODE].end = _etext;
			ksegm.seg[SEGMENT_CODE].name = "CODE";
			goto next_res;
		}
		if (!strncmp("Kernel rodata", iter->name, 13)) {
			ksegm.seg[SEGMENT_RODATA].start = __start_rodata;
			ksegm.seg[SEGMENT_RODATA].end = __end_rodata;
			ksegm.seg[1].name = "RODATA";
			goto next_res;
		}
		if (!strncmp("Kernel data", iter->name, 11)) {
			ksegm.seg[SEGMENT_DATA].start = _sdata;
			ksegm.seg[SEGMENT_DATA].end = _edata;
			ksegm.seg[SEGMENT_DATA].name = "DATA";
			goto next_res;
		}
		if (!strncmp("Kernel bss", iter->name, 10)) {
			ksegm.seg[SEGMENT_BSS].start = __bss_start;
			ksegm.seg[SEGMENT_BSS].end = __bss_stop;
			ksegm.seg[SEGMENT_BSS].name = "BSS";
			goto next_res;
		}
next_res:
		iter = iter->sibling;
	}
}

static void init_vmlinux_section(void)
{
	struct resource *resource = iomem_resource.child;
	struct resource *kernel_addr;
	struct addr_range *adr;
	bool found = false;
	while (resource) {
		if (strncmp("System RAM", resource->name, 10))
			goto next_res;
		kernel_addr = resource->child;
		if (kernel_addr) {
			if (strncmp("Kernel", kernel_addr->name, 6))
				goto next_res;
			found = true;
			store_kernel_address_range(kernel_addr);
			break;
		}
next_res:
		resource = resource->sibling;
	}

	for (int i = 0; i < NR_SEGMENTS; i++) {
		adr = &ksegm.seg[i];
	}
}

static int at_open(struct inode *inode, struct file *filp)
{
	return 0; /* success */
}

static int at_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static bool folio_data(struct folio *folio, struct vm_area_struct *vma,
		       unsigned long v_address, void *arg)
{
	struct task_struct *task = vma->vm_mm->owner;
	struct rwc_args data = *(struct rwc_args *)arg;
	unsigned long page_start = v_address;
	unsigned long long phys_addr_page_start;
	unsigned int offset_within_page;
	phys_addr_page_start = get_physical_address(page_start, task);
	offset_within_page = data.addr_to_be_resolved - phys_addr_page_start;
	dynamic_buffer_write("User Space,0x%llx,0x%lx,%d,%s\n",
			     data.addr_to_be_resolved,
			     v_address + offset_within_page, task->pid,
			     task->comm);
	user_address_count++;
	return true;
}

/*
 * TODO Get offset to memory in this
 */
static bool analyse_kmalloc_memory(const phys_addr_t addr)
{
	unsigned long caller;
	const char *ret;
	unsigned long symbolsize;
	unsigned long offset;
	char *modname;
	char *namebuf = temp_buffer;
	void *object = phys_to_virt(addr);
	struct slab *slab;
	struct kmem_cache *s;
	struct folio *folio;
	struct page *page = pfn_to_online_page(PHYS_PFN(addr));
	if (!page || PageTail(page))
		return NULL;
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
	ret = kallsyms_lookup(caller, &symbolsize, &offset, &modname, namebuf);
	if (ret) {
		dynamic_buffer_write(
			"kmalloc,0x%llx,0x%llx,%s+0x%lx/0x%lx,%s\n", addr,
			(unsigned long long)object, namebuf, offset, symbolsize,
			modname ? modname : "kernel");
		return true;
	}
	return false;
}

static bool analyse_vmalloc_memory(const phys_addr_t phys_addr)
{
	bool found = false;
	void *vaddr;
	unsigned long paddr;
	struct vmap_area *va;
	struct vm_struct *vm;
	struct page *page;

	list_for_each_entry(va, &vmap_area_list, list) {
		vm = va->vm;
		for(vaddr = vm->addr; vaddr < vm->addr + vm->size; vaddr += PAGE_SIZE) {
			page = vmalloc_to_page(vaddr);
			if(!page)
				continue;
			paddr = page_to_phys(page);
			if(phys_addr >= paddr && phys_addr < paddr + PAGE_SIZE) {
				found = true;
				goto done;
			}
		}
	}
	if (!found)
		return false;
done:
	dynamic_buffer_write("vmalloc space,0x%llx,0x%lx,%pS,kernel\n", phys_addr,
			     va->va_start,
			     va->vm->caller ? va->vm->caller : "NA");
	return true;
}

static bool analyse_kernel_symbols(const unsigned long long paddr)
{
	unsigned long symbolsize;
	unsigned long offset;
	char *modname;
	char *namebuf = temp_buffer;
	const char *ret;
	unsigned long long addr = (unsigned long long)phys_to_virt(paddr);
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

static bool analyse_vmlinux_section(const unsigned long long paddr)
{
	void *addr = phys_to_virt(paddr);
	for (int i = 0; i < NR_SEGMENTS; i++) {
		if (ksegm.seg[i].start <= addr && addr <= ksegm.seg[i].end) {
			dynamic_buffer_write(
				"vmlinux,0x%llx,0x%llx,%s,vmlinux\n", paddr,
				addr, ksegm.seg[i].name);
			return true;
		}
	}
	return false;
}

static void analyse_physical_address(const unsigned long long addr)
{
	struct rwc_args data;
	struct folio *folio = get_folio(PHYS_PFN(addr));
	struct rmap_walk_control rwc = {
		.rmap_one = folio_data,
		.arg = (void *)&data,
	};

	if (folio != NULL) {
		data.addr_to_be_resolved = addr;
		data.count = 0;
		rmap_walk(folio, &rwc);
	}
	if (user_address_count > 0) {
		user_address_count = 0;
		return;
	}

	if (analyse_kmalloc_memory(addr))
		return;

	if (analyse_kernel_symbols(addr))
		return;

	if (analyse_vmlinux_section(addr))
		return;

	if (analyse_vmalloc_memory(addr))
		return;

	dynamic_buffer_write("NA,0x%llx,,,,\n", addr);
}

static ssize_t at_write(struct file *filp, const char __user *buf, size_t count,
			loff_t *f_pos)
{
	char *data = temp_buffer;
	unsigned long long addr;
	count = min(count, TEMP_BUFFER_SIZE - 1);

	if (copy_from_user(data, buf, count))
		return -EFAULT;
	data[count] = '\0';

	if (count == 1 && data[0] == 0x0A) {
		reset_buffer();
		return count;
	}
	if (kstrtoull(data, 16, &addr)) {
		pr_warn("invalid address '%s'\n", data);
		return -EFAULT;
	}
	pr_debug("Device Wrote %lu bytes: 0x%llX", count, addr);
	analyse_physical_address(addr);
	return count;
}

static ssize_t at_read(struct file *file, char __user *buf, size_t count,
		       loff_t *ppos)
{
	size_t bytes_to_read;
	loff_t read_offset = *ppos;

	if (read_offset >= data_size) {
		return 0;
	}

	bytes_to_read = min(count, data_size - read_offset);
	bytes_to_read = min(bytes_to_read, CHUNK_SIZE);

	if (copy_to_user(buf, buffer + read_offset, bytes_to_read)) {
		pr_err("Failed to copy data to user space\n");
		return -EFAULT;
	}
	*ppos += bytes_to_read;
	return bytes_to_read;
}

static struct file_operations at_fops = {
	.owner = THIS_MODULE,
	.read = at_read,
	.write = at_write,
	.open = at_open,
	.release = at_release,
};

void __exit at_exit(void)
{
	debugfs_remove_recursive(debugfs_dir);
	kfree(buffer);
	kfree(temp_buffer);
	pr_info("Address Translation Module Unloaded\n");
}

int __init at_init(void)
{
	debugfs_dir = debugfs_create_dir(DEBUGFS_DIR_NAME, NULL);
	if (!debugfs_dir) {
		pr_err("Failed to create debugfs directory\n");
		return -ENOMEM;
	}

	debugfs_file = debugfs_create_file(DEBUGFS_FILE_NAME, 0644, debugfs_dir,
					   NULL, &at_fops);
	if (!debugfs_file) {
		pr_err("Failed to create debugfs file\n");
		debugfs_remove_recursive(debugfs_dir);
		return -ENOMEM;
	}
	buffer = kmalloc(INITIAL_BUFFER_SIZE, GFP_KERNEL);
	if (!buffer) {
		pr_err("Failed to allocate memory for dynamic buffer\n");
		return -ENOMEM;
	}
	temp_buffer = kmalloc(TEMP_BUFFER_SIZE, GFP_KERNEL);
	if (!temp_buffer) {
		pr_err("Failed to allocate memory for temporary buffer\n");
		return -ENOMEM;
	}
	reset_buffer();
	pr_info("Virtual Address of init %llx\n", (unsigned long long)at_init);
	pr_info("Virtual Address of temp_buffer 0x%px\n", temp_buffer);
	pr_info("Phy Address of temp_buffer 0x%llx\n",
		virt_to_phys(temp_buffer));
	pr_info("Virtual addr after Cnversion of temp_buffer 0x%px\n",
		phys_to_virt(virt_to_phys(temp_buffer)));

	init_vmlinux_section();
	analyse_kmalloc_memory(__pa(temp_buffer));
	printk(KERN_INFO "CODE\t%px - %px\n", _stext, _etext);
	printk(KERN_INFO "DATA\t%px - %px\n", _sdata, _edata);
	printk(KERN_INFO "RODATA\t%px - %px\n", __start_rodata, __end_rodata);
	printk(KERN_INFO "BSS\t%px - %px\n", __bss_start, __bss_stop);
	return 0;
}

module_init(at_init);
module_exit(at_exit);

MODULE_AUTHOR("Mukesh Kumar Chaurasiya");
MODULE_DESCRIPTION("Address Translation Module");
MODULE_LICENSE("GPL");
