#include "asm-generic/errno-base.h"
#include "asm-generic/memory_model.h"
#include "linux/printk.h"
#include "linux/stddef.h"
#include "linux/vmalloc.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mm.h>

int __init at_test_init(void);
void __exit at_test_exit(void);

static int *test = NULL;

void __exit at_test_exit(void)
{
	pr_info("Address Translation Test Module Unloaded\n");
	vfree(test);
}

int __init at_test_init(void)
{
	void *p = NULL;
	int i;
	pr_info("########### Address Translation Test Module Loaded ###########\n");
	test = (int *)vmalloc(16507);
	if (test == NULL) {
		pr_err("Unable to allocate Memory\n");
	} else {
		pr_info("Memory address: 0x%px\n", test);
	}
	memset(test, 0, 16507);
	struct vmap_area *vma = find_vmap_area((unsigned long)test);
	if (vma == NULL) {
		pr_err("Unable to find vmap area\n");
		return -EFAULT;
	}
	for (i = 0; i < vma->vm->nr_pages; i++) {
		p = page_address(vma->vm->pages[i]);
		pr_info("Physical Address of memory is %px\n", p);
	}
	return 0;
}

module_init(at_test_init);
module_exit(at_test_exit);

MODULE_AUTHOR("Mukesh Kumar Chaurasiya");
MODULE_DESCRIPTION("Address Translation Test Module");
MODULE_LICENSE("GPL");
