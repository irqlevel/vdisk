#include "vdisk-malloc-checker.h"
#include "vdisk-helpers.h"

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/crc32.h>
#include <linux/stacktrace.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define MALLOC_CHECKER_STACK_ENTRIES 10
#define MALLOC_CHECKER_NR_LISTS 9973
#define MALLOC_CHECKER_SIGN1 0xBEDABEDA
#define MALLOC_CHECKER_SIGN2 0xCBDACBDA

struct malloc_entry {
	struct list_head link;
	gfp_t flags;
	void *ptr;
	size_t size;
#ifdef __MALLOC_CHECKER_STACK_TRACE__
	struct stack_trace stack;
	unsigned long stack_entries[MALLOC_CHECKER_STACK_ENTRIES];
	char stack_buf[512];
#endif
#ifdef __MALLOC_CHECKER_DELAY_FREE__
	u32 crc32;
	ktime_t time_to_live;
#endif
};

struct malloc_checker {
	struct list_head entries_list[MALLOC_CHECKER_NR_LISTS];
	spinlock_t	 entries_list_lock[MALLOC_CHECKER_NR_LISTS];
	atomic64_t	 nr_allocs;
	atomic64_t	 nr_frees;
#ifdef __MALLOC_CHECKER_DELAY_FREE__
	struct task_struct *delay_check_thread;
	struct list_head delay_entries_list[MALLOC_CHECKER_NR_LISTS];
	spinlock_t	 delay_entries_list_lock[MALLOC_CHECKER_NR_LISTS];
#endif
};

static struct malloc_checker g_malloc_checker;

#ifdef __MALLOC_CHECKER_DELAY_FREE__

static void release_entry(struct malloc_checker *checker,
			  struct malloc_entry *entry)
{
	unsigned long *psign1, *psign2;
	void *ptr = entry->ptr;

	psign1 = (unsigned long *)((unsigned long)ptr - sizeof(unsigned long));
	psign2 = (unsigned long *)((unsigned long)ptr + entry->size);

	WARN_ON(*psign1 != MALLOC_CHECKER_SIGN1);
	WARN_ON(*psign2 != MALLOC_CHECKER_SIGN2);

#ifdef __MALLOC_CHECKER_FILL_CC__
	memset(entry->ptr, 0xCC, entry->size);
#endif

#ifdef __MALLOC_CHECKER_PRINTK__
	PRINTK("free entry %p ptr %p\n", entry, entry->ptr);
#endif

	kfree(psign1);
	kfree(entry);
}

static void delay_check(struct malloc_checker *checker,
			struct malloc_entry *entry)
{
	unsigned long *psign1, *psign2;
	void *ptr = entry->ptr;

	psign1 = (unsigned long *)((unsigned long)ptr - sizeof(unsigned long));
	psign2 = (unsigned long *)((unsigned long)ptr + entry->size);

	WARN_ON(*psign1 != MALLOC_CHECKER_SIGN1);
	WARN_ON(*psign2 != MALLOC_CHECKER_SIGN2);
	WARN_ON(entry->crc32 != crc32_le(~0, entry->ptr, entry->size));

#ifdef __MALLOC_CHECKER_PRINTK__
	PRINTK("delay check entry %p ptr %p\n", entry, entry->ptr);
#endif
}

static int malloc_checker_delay_thread(void *data)
{
	struct malloc_checker *checker = (struct malloc_checker *)data;
	unsigned long irq_flags;
	struct list_head free_list;
	struct malloc_entry *curr, *tmp;
	unsigned long i;

	PRINTK("starting\n");

	while (!kthread_should_stop()) {
		msleep(100);

		INIT_LIST_HEAD(&free_list);
		for (i = 0; i < ARRAY_SIZE(checker->delay_entries_list); i++) {

			INIT_LIST_HEAD(&free_list);
			spin_lock_irqsave(&checker->delay_entries_list_lock[i],
					  irq_flags);
			list_for_each_entry_safe(curr, tmp,
				&checker->delay_entries_list[i],
				link) {
				delay_check(checker, curr);
				if (ktime_compare(curr->time_to_live,
						  ktime_get()) >= 0) {
					list_del(&curr->link);
					list_add(&curr->link, &free_list);
				}
			}
			spin_unlock_irqrestore(
				&checker->delay_entries_list_lock[i],
				irq_flags);
		}

		list_for_each_entry_safe(curr, tmp, &free_list, link) {
			list_del_init(&curr->link);
			release_entry(checker, curr);
		}
	}

	PRINTK("stopping\n");

	return 0;
}
#endif

int malloc_checker_init(void)
{
	struct malloc_checker *checker = &g_malloc_checker;
	unsigned long i;

	PRINTK("malloc checker init\n");

	atomic64_set(&checker->nr_allocs, 0);
	atomic64_set(&checker->nr_frees, 0);

	for (i = 0; i < ARRAY_SIZE(checker->entries_list); i++) {
		INIT_LIST_HEAD(&checker->entries_list[i]);
		spin_lock_init(&checker->entries_list_lock[i]);
	}

#ifdef __MALLOC_CHECKER_DELAY_FREE__
	{
		struct task_struct *thread;

		for (i = 0; i < ARRAY_SIZE(checker->delay_entries_list); i++) {
			INIT_LIST_HEAD(&checker->delay_entries_list[i]);
			spin_lock_init(&checker->delay_entries_list_lock[i]);
		}

		thread = kthread_create(malloc_checker_delay_thread, checker,
					"%s", "vdisk-malloc-checker");
		if (IS_ERR(thread))
			return PTR_ERR(thread);

		get_task_struct(thread);
		checker->delay_check_thread = thread;
		wake_up_process(thread);
	}
#endif
	return 0;
}

void *malloc_checker_kmalloc(size_t size, gfp_t flags)
{
	struct malloc_checker *checker = &g_malloc_checker;
	struct malloc_entry *entry;
	unsigned long *psign1, *psign2;
	void *ptr;
	unsigned long i;
	unsigned long irq_flags;

	entry = kmalloc(sizeof(*entry), flags);
	if (!entry)
		return NULL;

	memset(entry, 0, sizeof(*entry));

	psign1 = kmalloc(size + 2*sizeof(unsigned long), flags);
	if (!psign1) {
		kfree(entry);
		return NULL;
	}

	ptr = (void *)((unsigned long)psign1 + sizeof(unsigned long));
	psign2 = (unsigned long *)((unsigned long)ptr + size);
	*psign1 = MALLOC_CHECKER_SIGN1;
	*psign2 = MALLOC_CHECKER_SIGN2;

	entry->ptr = ptr;
	entry->size = size;
	entry->flags = flags;
	INIT_LIST_HEAD(&entry->link);

#ifdef __MALLOC_CHECKER_STACK_TRACE__
	entry->stack.nr_entries = 0;
	entry->stack.max_entries = ARRAY_SIZE(entry->stack_entries);
	entry->stack.entries = entry->stack_entries;
	entry->stack.skip = 2;
	save_stack_trace(&entry->stack);
	snprint_stack_trace(entry->stack_buf, ARRAY_SIZE(entry->stack_buf),
			    &entry->stack, 0);
#endif

	i = vdisk_hash_pointer(ptr) % ARRAY_SIZE(checker->entries_list);
	spin_lock_irqsave(&checker->entries_list_lock[i], irq_flags);
	list_add(&entry->link, &checker->entries_list[i]);
	spin_unlock_irqrestore(&checker->entries_list_lock[i], irq_flags);

	atomic64_inc(&checker->nr_allocs);

#ifdef __MALLOC_CHECKER_PRINTK__
	PRINTK("alloc entry %p ptr %p\n", entry, entry->ptr);
#endif

	return ptr;
}

static void check_and_release_entry(struct malloc_checker *checker,
				    struct malloc_entry *entry)
{
	unsigned long *psign1, *psign2;
	void *ptr = entry->ptr;

	psign1 = (unsigned long *)((unsigned long)ptr - sizeof(unsigned long));
	psign2 = (unsigned long *)((unsigned long)ptr + entry->size);

	WARN_ON(*psign1 != MALLOC_CHECKER_SIGN1);
	WARN_ON(*psign2 != MALLOC_CHECKER_SIGN2);

#ifdef __MALLOC_CHECKER_FILL_CC__
	memset(entry->ptr, 0xCC, entry->size);
#endif

#ifdef __MALLOC_CHECKER_PRINTK__
	PRINTK("free entry %p ptr %p\n", entry, entry->ptr);
#endif

#ifdef __MALLOC_CHECKER_DELAY_FREE__
	entry->crc32 = crc32_le(~0, entry->ptr, entry->size);
	entry->time_to_live = ktime_add_ns(ktime_get(), 1000000000);
	{
		unsigned long irq_flags;
		unsigned long i;

		i = hash_pointer(ptr) % ARRAY_SIZE(checker->delay_entries_list);
		spin_lock_irqsave(&checker->delay_entries_list_lock[i],
				  irq_flags);
		list_add(&entry->link, &checker->delay_entries_list[i]);
		spin_unlock_irqrestore(&checker->delay_entries_list_lock[i],
				       irq_flags);
	}
#else
	kfree(psign1);
	kfree(entry);
#endif
}

void malloc_checker_kfree(void *ptr)
{
	struct malloc_checker *checker = &g_malloc_checker;
	unsigned long i;
	unsigned long irq_flags;
	struct malloc_entry *curr, *tmp;
	struct list_head entries_list;

	INIT_LIST_HEAD(&entries_list);
	i = vdisk_hash_pointer(ptr) % ARRAY_SIZE(checker->entries_list);
	spin_lock_irqsave(&checker->entries_list_lock[i], irq_flags);
	list_for_each_entry_safe(curr, tmp, &checker->entries_list[i], link) {
		if (curr->ptr == ptr) {
			list_del(&curr->link);
			list_add(&curr->link, &entries_list);
		}
	}

	spin_unlock_irqrestore(&checker->entries_list_lock[i], irq_flags);

	list_for_each_entry_safe(curr, tmp, &entries_list, link) {
		list_del_init(&curr->link);
		check_and_release_entry(checker, curr);
		atomic64_inc(&checker->nr_frees);
	}
}

void malloc_checker_deinit(void)
{
	unsigned long i;
	unsigned long irq_flags;
	struct list_head entries_list;
	struct malloc_entry *curr, *tmp;
	struct malloc_checker *checker = &g_malloc_checker;

	PRINTK("malloc checker deinit: nr_allocs %ld nr_frees %ld\n",
	       atomic64_read(&checker->nr_allocs),
	       atomic64_read(&checker->nr_frees));

#ifdef __MALLOC_CHECKER_DELAY_FREE__
	kthread_stop(checker->delay_check_thread);
	put_task_struct(checker->delay_check_thread);
#endif

	for (i = 0; i < ARRAY_SIZE(checker->entries_list); i++) {
		INIT_LIST_HEAD(&entries_list);
		spin_lock_irqsave(&checker->entries_list_lock[i], irq_flags);
		list_for_each_entry_safe(curr, tmp, &checker->entries_list[i],
					 link) {
			list_del(&curr->link);
			list_add(&curr->link, &entries_list);
		}
		spin_unlock_irqrestore(&checker->entries_list_lock[i],
				       irq_flags);

		list_for_each_entry_safe(curr, tmp, &entries_list, link) {
			list_del_init(&curr->link);
			PRINTK("leak entry %p ptr %p size %lu flags 0x%x\n",
			       curr, curr->ptr, curr->size, curr->flags);
#ifdef __MALLOC_CHECKER_STACK_TRACE__
			PRINTK("leak entry stack %s\n", curr->stack_buf);
#endif
			check_and_release_entry(checker, curr);
		}
	}

#ifdef __MALLOC_CHECKER_DELAY_FREE__
	for (i = 0; i < ARRAY_SIZE(checker->delay_entries_list); i++) {
		INIT_LIST_HEAD(&entries_list);
		spin_lock_irqsave(&checker->delay_entries_list_lock[i],
				  irq_flags);
		list_for_each_entry_safe(curr, tmp,
				&checker->delay_entries_list[i],
				link) {
			list_del(&curr->link);
			list_add(&curr->link, &entries_list);
		}

		spin_unlock_irqrestore(&checker->delay_entries_list_lock[i],
				       irq_flags);

		list_for_each_entry_safe(curr, tmp, &entries_list, link) {
			list_del_init(&curr->link);
			delay_check(checker, curr);
			release_entry(checker, curr);
		}
	}
#endif
}
