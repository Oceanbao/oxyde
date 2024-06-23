#![allow(dead_code)]

// NOTE: there is a confusion on Rc<RefCell<T>> calling
// .borrow() fails for unknown type
// .borrow_mut() succeeds directly accessing RefCell::borrow_mut() -> RefMut<T>
// The reason is that Rc<T> can directly access methods of T
// but `borrow()` exists on both Rc<T> and RefCell<T>, hence causing confusion.
// but `borrow_mut()` does not impl for Rc<T> by default. (in this case on RefCell<T>)

use std::{
    cell::{Ref, RefCell, RefMut},
    rc::Rc,
};

struct List<T> {
    head: NodeRef<T>,
    tail: NodeRef<T>,
}

type NodeRef<T> = Option<Rc<RefCell<Node<T>>>>;

struct Node<T> {
    data: T,
    prev: NodeRef<T>,
    next: NodeRef<T>,
}

impl<T> Node<T> {
    fn new(data: T) -> Rc<RefCell<Self>> {
        Rc::new(RefCell::new(Node {
            data,
            prev: None,
            next: None,
        }))
    }
}

impl<T> List<T> {
    fn new() -> Self {
        List {
            head: None,
            tail: None,
        }
    }

    fn prepend(&mut self, data: T) {
        let new_head = Node::new(data);
        match self.head.take() {
            Some(old_head) => {
                old_head.borrow_mut().prev = Some(new_head.clone());
                new_head.borrow_mut().next = Some(old_head);
                self.head = Some(new_head);
            }
            None => {
                self.tail = Some(new_head.clone());
                self.head = Some(new_head);
            }
        }
    }

    fn push(&mut self, data: T) {
        let new_tail = Node::new(data);
        match self.tail.take() {
            Some(old_tail) => {
                old_tail.borrow_mut().next = Some(new_tail.clone());
                new_tail.borrow_mut().prev = Some(old_tail);
                self.tail = Some(new_tail);
            }
            None => {
                self.head = Some(new_tail.clone());
                self.tail = Some(new_tail);
            }
        }
    }

    fn pop(&mut self) -> Option<T> {
        self.tail.take().map(|old_tail| {
            match old_tail.borrow_mut().prev.take() {
                Some(new_tail) => {
                    new_tail.borrow_mut().next.take();
                    self.tail = Some(new_tail);
                }
                None => {
                    self.head.take();
                }
            };
            // NOTE: the chaining of try Result-Ok-Option-unwrap
            Rc::try_unwrap(old_tail).ok().unwrap().into_inner().data
        })
    }

    fn shift(&mut self) -> Option<T> {
        self.head.take().map(|old_head| {
            match old_head.borrow_mut().next.take() {
                Some(new_head) => {
                    new_head.borrow_mut().prev.take();
                    self.head = Some(new_head);
                }
                None => {
                    self.tail.take();
                }
            };
            Rc::try_unwrap(old_head).ok().unwrap().into_inner().data
        })
    }

    fn peek_front(&self) -> Option<Ref<T>> {
        self.head
            .as_ref()
            .map(|node| Ref::map(node.as_ref().borrow(), |n| &n.data))
    }
    fn peek_back(&self) -> Option<Ref<T>> {
        self.tail
            .as_ref()
            .map(|node| Ref::map(node.as_ref().borrow(), |node| &node.data))
    }

    fn peek_back_mut(&mut self) -> Option<RefMut<T>> {
        self.tail
            .as_ref()
            .map(|node| RefMut::map(node.borrow_mut(), |node| &mut node.data))
    }

    fn peek_front_mut(&mut self) -> Option<RefMut<T>> {
        self.head
            .as_ref()
            .map(|node| RefMut::map(node.borrow_mut(), |node| &mut node.data))
    }

    fn into_iter(self) -> IntoIter<T> {
        IntoIter(self)
    }
}

impl<T> Drop for List<T> {
    fn drop(&mut self) {
        while self.shift().is_some() {}
    }
}

pub struct IntoIter<T>(List<T>);

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        self.0.shift()
    }
}

impl<T> DoubleEndedIterator for IntoIter<T> {
    fn next_back(&mut self) -> Option<T> {
        self.0.pop()
    }
}

#[cfg(test)]
mod test {
    use super::List;

    #[test]
    fn basics() {
        let mut list = List::new();

        // Check empty list behaves right
        assert_eq!(list.shift(), None);

        // Populate list
        list.prepend(1);
        list.prepend(2);
        list.prepend(3);

        // Check normal removal
        assert_eq!(list.shift(), Some(3));
        assert_eq!(list.shift(), Some(2));

        // Push some more just to make sure nothing's corrupted
        list.prepend(4);
        list.prepend(5);

        // Check normal removal
        assert_eq!(list.shift(), Some(5));
        assert_eq!(list.shift(), Some(4));

        // Check exhaustion
        assert_eq!(list.shift(), Some(1));
        assert_eq!(list.shift(), None);

        // ---- back -----

        // Check empty list behaves right
        assert_eq!(list.pop(), None);

        // Populate list
        list.push(1);
        list.push(2);
        list.push(3);

        // Check normal removal
        assert_eq!(list.pop(), Some(3));
        assert_eq!(list.pop(), Some(2));

        // Push some more just to make sure nothing's corrupted
        list.push(4);
        list.push(5);

        // Check normal removal
        assert_eq!(list.pop(), Some(5));
        assert_eq!(list.pop(), Some(4));

        // Check exhaustion
        assert_eq!(list.pop(), Some(1));
        assert_eq!(list.pop(), None);
    }

    #[test]
    fn peek() {
        let mut list = List::new();
        assert!(list.peek_front().is_none());
        assert!(list.peek_back().is_none());
        assert!(list.peek_front_mut().is_none());
        assert!(list.peek_back_mut().is_none());

        list.prepend(1);
        list.prepend(2);
        list.prepend(3);

        assert_eq!(&*list.peek_front().unwrap(), &3);
        assert_eq!(&mut *list.peek_front_mut().unwrap(), &mut 3);
        assert_eq!(&*list.peek_back().unwrap(), &1);
        assert_eq!(&mut *list.peek_back_mut().unwrap(), &mut 1);
    }

    #[test]
    fn into_iter() {
        let mut list = List::new();
        list.prepend(1);
        list.prepend(2);
        list.prepend(3);

        let mut iter = list.into_iter();
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next_back(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next_back(), None);
        assert_eq!(iter.next(), None);
    }
}
