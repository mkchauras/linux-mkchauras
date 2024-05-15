#include "asm-generic/errno-base.h"
#include "asm-generic/memory_model.h"
#include "asm/io.h"
#include "linux/align.h"
#include "linux/printk.h"
#include "linux/vmalloc.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>

static unsigned long get_vmalloc_physical_address(void *vaddr);
int __init at_test_init(void);
void __exit at_test_exit(void);

static int *test = NULL;
static char *test_kmalloc = NULL;

static unsigned long get_vmalloc_physical_address(void *vaddr)
{
	struct page *page;
	unsigned long paddr = 0;

	page = vmalloc_to_page(vaddr);
	if (page) {
		paddr = page_to_phys(page) + offset_in_page(vaddr);
	}

	return paddr;
}

void __exit at_test_exit(void)
{
	pr_info("Address Translation Test Module Unloaded\n");
	kfree(test_kmalloc);
	vfree(test);
}

int __init at_test_init(void)
{
	void *p = NULL;
	int i;
	pr_info("########### Address Translation Test Module Loaded ###########\n");
	test = (int *)vmalloc(65537);
	test_kmalloc = (char *)kmalloc(256, GFP_KERNEL);
	if (test == NULL || test_kmalloc == NULL) {
		pr_err("Unable to allocate Memory\n");
	}
	memset(test, 0, 16507);
	memset(test_kmalloc, 0, 256);
	pr_info("Phys Memory address of 0x%px vmalloc: 0x%lx\n", test,
		get_vmalloc_physical_address(test));
	pr_info("Phys Memory address kmalloc: 0x%llx\n",
		virt_to_phys(test_kmalloc));
	pr_info("Vmalloc: Start: 0x%lx\tEnd: 0x%lx\n", VMALLOC_START, VMALLOC_END);
	struct vmap_area *vma = find_vmap_area((unsigned long)test);
	if (vma == NULL) {
		pr_err("Unable to find vmap area\n");
		return -EFAULT;
	}
	for (i = 0; i < vma->vm->nr_pages; i++) {
		p = page_address(vma->vm->pages[i]);
		pr_info("Physical Address of memory is %llx\n",
			vma->vm->phys_addr);
	}
	return 0;
}

module_init(at_test_init);
module_exit(at_test_exit);

MODULE_AUTHOR("Mukesh Kumar Chaurasiya");
MODULE_DESCRIPTION("Address Translation Test Module");
MODULE_LICENSE("GPL");
