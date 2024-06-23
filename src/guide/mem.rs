#![allow(dead_code, unused_variables)]

fn heap_alloc() {
    let heap_int = Box::new(1);
    let heap_int_vec = vec![0; 100];
    let heap_string = String::from("heap string");
}

fn stack_alloc() {
    let stack_int = 69420;
    let stack_string = "stack string";
}

fn ownership() {
    let mut top_grossing_films = vec!["Avatar", "Avengers", "Titanic"];
    let top_grossing_films_mutable_reference = &mut top_grossing_films;
    top_grossing_films_mutable_reference.push("Star Wars");
    // Exclusive-Write (mut-ref), hence below Read makes above invalid.
    let top_grossing_films_reference = &top_grossing_films;

    println!("Printed using ref: {:#?}", top_grossing_films_reference);

    // MOVE ownership.
    let top_grossing_films_moved = top_grossing_films;

    println!("Printed after moving: {:#?}", top_grossing_films_moved);

    // No longer valid after move.
    // println!("Print using original value: {:#?}", top_grossing_films);

    // Recall above mut-ref invalidated once Read ref created.
    // println!(
    //     "Print using mut-ref: {:#?}",
    //     top_grossing_films_mutable_reference
    // );
}

// Singly-Linked List
#[derive(Clone)]
struct ListItem<T> {
    data: Box<T>,
    next: Option<Box<ListItem<T>>>,
}

struct SinglyLinkedList<T> {
    head: ListItem<T>,
}

impl<T> ListItem<T> {
    fn new(data: T) -> Self {
        ListItem {
            data: Box::new(data),
            next: None,
        }
    }

    fn next(&self) -> Option<&Self> {
        if let Some(next) = &self.next {
            Some(next)
        } else {
            None
        }
    }

    fn mut_tail(&mut self) -> &mut Self {
        if self.next.is_some() {
            self.next.as_mut().unwrap().mut_tail()
        } else {
            self
        }
    }

    fn data(&self) -> &T {
        self.data.as_ref()
    }
}

impl<T> SinglyLinkedList<T> {
    fn new(data: T) -> Self {
        SinglyLinkedList {
            head: ListItem::new(data),
        }
    }

    fn append(&mut self, data: T) {
        let tail = self.head.mut_tail();
        tail.next = Some(Box::new(ListItem::new(data)));
    }

    fn head(&self) -> &ListItem<T> {
        &self.head
    }
}

fn run_singlylist() {
    let mut list = SinglyLinkedList::new("head");
    list.append("middle");
    list.append("tail");
    let mut item = list.head();
    loop {
        println!("item: {}", item.data());
        if let Some(next_item) = item.next() {
            item = next_item;
        } else {
            break;
        }
    }
}

// Box OWN the data, cannot be shared.
// `Rc` a single-threaded ref-count sharing ownership.
// `Arc` a multi-threaded ref-count sharing ownership.
//
// To get more flexible with MUT-REF, comes interior-mutability
// `RefCell` over `Cell` since it allows borrow references, instead
// of MOVE value in and out of iteself (mostly not desired)
// (sign of these is alert on redesign)
// (single-threaded, need Mutex or RwLock - often used with Arc)

use std::borrow::Cow;
// Doubly-Linked List cannot be impl using Box, since no sharing ownership.
use std::cell::RefCell;
use std::rc::Rc;

struct Node<T> {
    prev: Option<NodeRef<T>>,
    data: Box<T>,
    next: Option<NodeRef<T>>,
}

type NodeRef<T> = Rc<RefCell<Node<T>>>;

struct DoublyLinkedList<T> {
    head: NodeRef<T>,
}

impl<T> Node<T> {
    fn new(data: T) -> Self {
        Node {
            prev: None,
            data: Box::new(data),
            next: None,
        }
    }

    fn data(&self) -> &T {
        self.data.as_ref()
    }
}

impl<T> DoublyLinkedList<T> {
    fn new(data: T) -> Self {
        DoublyLinkedList {
            head: Rc::new(RefCell::new(Node::new(data))),
        }
    }

    // Recursively find tail.
    fn find_tail(item: NodeRef<T>) -> NodeRef<T> {
        // NOTE: how to access `next` from a Rc<RefCell<T>> and `&` it for read borrow.
        if let Some(next) = &item.as_ref().borrow().next {
            Self::find_tail(next.clone())
        } else {
            item.clone()
        }
    }

    // WRITE tail item's field.
    // NOTE: use of `clone` everywhere since cannot WRITE value using MOVE.
    fn append(&mut self, data: T) {
        let tail = Self::find_tail(self.head.clone());
        let new_item = Rc::new(RefCell::new(Node::new(data)));
        new_item.as_ref().borrow_mut().prev = Some(tail.clone());
        tail.as_ref().borrow_mut().next = Some(new_item);
    }

    fn head(&self) -> NodeRef<T> {
        self.head.clone()
    }

    fn tail(&self) -> NodeRef<T> {
        Self::find_tail(self.head())
    }
}

#[cfg(test)]
mod test {
    use super::DoublyLinkedList;

    #[test]
    fn test_doublylist() {
        let mut doublylist = DoublyLinkedList::new("first");
        doublylist.append("second");
        doublylist.append("third");

        assert_eq!(
            doublylist.head().as_ref().borrow().data.to_string(),
            "first".to_string()
        );
        assert_eq!(
            doublylist.tail().as_ref().borrow().data.to_string(),
            "third".to_string()
        );
    }
}

// Copy (`clone`) On Write
// `Cow` an enum-based smart pointer with useful semantics.
// `Rc, Arc` provide clone on write semantics with `make_mut()`.
// `Cow` will try to borrow a type alap and only make owned clone if necessary, on first write.
// e.g. Taking Cow would not care &str or String, and would instead try most efficient type.
struct NameLengthCow<'a> {
    name: Cow<'a, str>,
    length: usize,
}
impl<'a> NameLengthCow<'a> {
    // User not need to setup length
    fn new<S>(name: S) -> Self
    where
        S: Into<Cow<'a, str>>,
    {
        let name: Cow<'a, str> = name.into();
        NameLengthCow {
            length: name.len(),
            name,
        }
    }
}

#[derive(Clone)]
struct SinglyLinkedListCow<'a, T>
where
    T: Clone,
{
    // head pointer is stored within Cow - need lifetime so that struct and head lifetime same
    head: Cow<'a, ListItem<T>>,
}

impl<T> ListItem<T>
where
    T: Clone,
{
    fn new_cow(data: T) -> Self {
        ListItem {
            data: Box::new(data),
            next: None,
        }
    }

    fn next_cow(&self) -> Option<&Self> {
        if let Some(next) = &self.next {
            Some(next)
        } else {
            None
        }
    }

    fn mut_tail_cow(&mut self) -> &mut Self {
        if self.next.is_some() {
            self.next.as_mut().unwrap().mut_tail()
        } else {
            self
        }
    }

    fn data_cow(&self) -> &T {
        self.data.as_ref()
    }
}

impl<'a, T> SinglyLinkedListCow<'a, T>
where
    T: Clone,
{
    fn new(data: T) -> Self {
        SinglyLinkedListCow {
            head: Cow::Owned(ListItem::new(data)),
        }
    }

    fn append(&self, data: T) -> Self {
        let mut new_list = self.clone();
        let tail = new_list.head.to_mut().mut_tail();
        tail.next = Some(Box::new(ListItem::new(data)));
        new_list
    }

    fn head(&self) -> &ListItem<T> {
        &self.head
    }
}

// Custom Memory Allocator (local)
// std/alloc/trait.ALlocator

// Flag
#[cfg(target_family = "unix")]
fn get_platform() -> String {
    "UNIX".into()
}

#[cfg(target_family = "windows")]
fn get_platform() -> String {
    "UNIX".into()
}

fn cfg_func() {
    println!("This code is running on a {} family OS", get_platform());
    if cfg!(target_feature = "avx2") {
        println!("avx2 is enabled");
    } else {
        println!("avx2 is disabled");
    }
    if cfg!(not(any(target_arch = "x86", target_arch = "x86_64"))) {
        println!("This code is running on a non-Intel CPU");
    }
}
