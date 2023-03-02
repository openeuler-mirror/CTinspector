#ifndef TRANS_LIST_H
#define TRANS_LIST_H

#include <stddef.h>

struct ub_list {
	struct ub_list *next, *prev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct ub_list name = LIST_HEAD_INIT(name)

/**
 * ub_list_init - Initialize a ub_list structure
 * @list: ub_list structure to be initialized.
 *
 * Initializes the ub_list to point to itself.  If it is a list header,
 * the result is an empty list.
 */
static inline void ub_list_init(struct ub_list *list)
{
        list->next = list;
        list->prev = list;
}

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:        the pointer to the member.
 * @type:       the type of the container struct this is embedded in.
 * @member:     the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct ub_list pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the ub_list within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the ub_list within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the ub_list within the struct.
 */
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_entry_is_head - test if the entry points to the head of the list
 * @pos:        the type * to cursor
 * @head:       the head for your list.
 * @member:     the name of the ub_list within the struct.
 */
#define list_entry_is_head(pos, head, member)                           \
        (&pos->member == (head))

/**
 * ub_list_is_empty - test if the list is empty
 * @list:       the head for your list.
 */
static inline int ub_list_is_empty(const struct ub_list *list)
{
    return list->next == list;
}

/**
 * list_for_each_entry_safe - iterate over list of given type safe against removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the ub_list within the struct.
 */
#define UB_LIST_FOR_EACH_SAFE(pos, n, member, head)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_next_entry(n, member))

/**
 * UB_LIST_FOR_EACH - iterate over a list
 * @pos:        the &struct ub_list to use as a loop cursor.
 * @member:	    the name of the ub_list within the struct.
 * @head:       the head for your list.
 */
#define UB_LIST_FOR_EACH(pos, member, head)			\
	for (pos = list_first_entry(head, typeof(*pos), member);	\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = list_next_entry(pos, member))

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_add(struct ub_list *new,
                              struct ub_list *prev,
                              struct ub_list *next)
{
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

/**
 * ub_list_push_back - add a new entry at the tail of list
 * @new: new entry to be added
 * @head: list head to add it before
 *
 * Insert a new entry before the specified head.
 * This is useful for implementing queues.
 */
static inline void ub_list_push_back(struct ub_list *head, struct ub_list *new)
{
        __list_add(new, head->prev, head);
}

/**
 * ub_list_push_head - add a new entry at the head of list
 * @new: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is useful for implementing queues.
 */
static inline void ub_list_push_head(struct ub_list *new, struct ub_list *head)
{
        __list_add(new, head, head->next);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct ub_list * prev, struct ub_list * next)
{
        next->prev = prev;
        prev->next = next;
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void __list_del_entry(struct ub_list *entry)
{
        __list_del(entry->prev, entry->next);
}

/**
 * ub_list_remove - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void ub_list_remove(struct ub_list *entry)
{
        __list_del_entry(entry);
        entry->next = NULL;
        entry->prev = NULL;
}

#endif /*TRANS_LIST_H*/