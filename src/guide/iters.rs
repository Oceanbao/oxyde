#![allow(dead_code, unused_variables)]

// Implement own Iterator
// - a struct to hold state
// - impl `Iterator` for it
struct Counter {
    count: usize,
}

impl Counter {
    fn new() -> Counter {
        Counter { count: 0 }
    }
}

impl Iterator for Counter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        self.count += 1;
        if self.count < 6 {
            Some(self.count)
        } else {
            None
        }
    }
}

// std has one subtle bit: implementation of IntoIterator
// `impl<I: Iterator> IntoIterator for I`
// aka all `Iterator` impl `IntoIterator` (.into_iter())
//
// `Iterator` trait tells how to iterate once created an iterator!!!
// `IntoIterator` trait defines how to create an iterator for T.
//
// So creating own `struct COLLECTION<T> {}` should impl `IntoIterator`.
// `struct IntoIter<T> {}` create a struct to hold state
// `impl Iterator for IntoIter<T> {}`
//
// impl IntoIterator for COLLECTION<T> - for x in c
// impl IntoIterator for &COLLECTION<T> - for x in &c
// impl IntoIterator for &mut COLLECTION<T> for x in &mut c
// now can call `COLLECTION.into_iter() -> Iterator<T>`
//
// To get handy method (by convention) .iter() and .iter_mut():
// `struct Iter<T>` - holding &COLLECTION<T> state for shared iteration
// `struct IterMut<T>` - same but for &mut
// `impl Iterator for Iter<T>`
// `impl Iterator for IterMut<T>`
// implement handly methods on COLLECTION:
// COLLECTION::iter(&self) -> Iter
// COLLECTION::iter_mut(&self) -> IterMut
struct Grid {
    x: Vec<u32>,
    y: Vec<u32>,
}

struct GridIter {
    grid: Grid,
    i: usize,
    j: usize,
}

impl Iterator for GridIter {
    type Item = (u32, u32);
    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.grid.x.len() {
            self.i = 0;
            self.j += 1;
            if self.j >= self.grid.y.len() {
                return None;
            }
        }
        let res = Some((self.grid.x[self.i], self.grid.y[self.j]));
        self.i += 1;
        res
    }
}

impl IntoIterator for Grid {
    type Item = (u32, u32);
    type IntoIter = GridIter;
    fn into_iter(self) -> Self::IntoIter {
        GridIter {
            grid: self,
            i: 0,
            j: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Counter, Grid};

    #[test]
    fn test_counter() {
        // Counter impl Iterator trait, it means it can .next()
        let mut c = Counter::new();
        assert_eq!(c.next(), Some(1));
        assert_eq!(c.next(), Some(2));
        assert_eq!(c.next(), Some(3));

        // std auto-impl IntoIterator for all Iterator.
        let cc = Counter::new();
        for x in cc {
            if x == 10 {
                break;
            }
        }

        // Consumes c and returns c the iterator.
        let c_into_iter = c.into_iter();
        // recall .iter() is handy method that needs to be implement for &T
        // let c_iter = c_into_iter.iter();
    }

    #[test]
    fn test_grid() {
        let grid = Grid {
            x: vec![3, 5, 7, 9],
            y: vec![10, 20, 30, 40],
        };
        for (x, y) in grid {
            println!("{x}, {y}");
        }
    }
}

use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::marker::PhantomData;
use std::rc::Rc;

type NodeData<T> = Rc<RefCell<T>>;
type NodeRef<T> = Rc<RefCell<Node<T>>>;

struct Node<T> {
    data: NodeData<T>,
    next: Option<NodeRef<T>>,
}

impl<T> Node<T> {
    fn new(data: T) -> Self {
        Self {
            data: Rc::new(RefCell::new(data)),
            next: None,
        }
    }
}

struct LinkedList<T> {
    head: NodeRef<T>,
    // curr_iter: Option<ListItemPtr<T>>,
}

impl<T> LinkedList<T> {
    fn new(t: T) -> Self {
        Self {
            head: Rc::new(RefCell::new(Node::new(t))),
            // curr_iter: None,
        }
    }

    fn append(&mut self, t: T) {
        // self.last()
        //     .expect("List was empty, but it should never be")
        //     .as_ref()
        //     .borrow_mut()
        //     .next = Some(Rc::new(RefCell::new(ListItem::new(t))));
        let mut next = self.head.clone();
        while next.as_ref().borrow().next.is_some() {
            let n = next.as_ref().borrow().next.as_ref().unwrap().clone();
            next = n;
        }
        next.as_ref().borrow_mut().next = Some(Rc::new(RefCell::new(Node::new(t))));
    }

    fn iter(&self) -> Iter<T> {
        Iter {
            next: Some(self.head.clone()),
            data: Some(self.head.as_ref().borrow().data.clone()),
            phantom: PhantomData,
        }
    }

    fn iter_mut(&mut self) -> IterMut<T> {
        IterMut {
            next: Some(self.head.clone()),
            data: Some(self.head.as_ref().borrow().data.clone()),
            phantom: PhantomData,
        }
    }

    fn into_iter(self) -> IntoIter<T> {
        IntoIter {
            next: Some(self.head.clone()),
        }
    }
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next.clone() {
            Some(ptr) => {
                self.next = ptr.as_ref().borrow().next.clone();
                self.data = Some(ptr.as_ref().borrow().data.clone());
                unsafe { Some(&*self.data.as_ref().unwrap().as_ptr()) }
            }
            None => None,
        }
    }
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next.clone() {
            Some(ptr) => {
                self.next = ptr.as_ref().borrow().next.clone();
                self.data = Some(ptr.as_ref().borrow().data.clone());
                unsafe { Some(&mut *self.data.as_ref().unwrap().as_ptr()) }
            }
            None => None,
        }
    }
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    // Both pointers to each item (or node) and data are stored in a
    // RefCell inside Rc.
    // Need try_unwrap on Rc to MOVE inner RefCell out of Rc since IntoIter
    // takes value; only works on Rc when no other refs, this is ok as no exposure
    // outside linked list.
    // Once RefCell out, need to MOVE T out of RefCell<T> with into_inner() to consume.
    fn next(&mut self) -> Option<Self::Item> {
        match self.next.clone() {
            Some(ptr) => {
                self.next = ptr.as_ref().borrow().next.clone();
                let item = Rc::try_unwrap(ptr).map(|refcell| refcell.into_inner());
                match item {
                    Ok(item) => Rc::try_unwrap(item.data)
                        .map(|refcell| refcell.into_inner())
                        .ok(),
                    Err(_) => None,
                }
            }
            None => None,
        }
    }
}

// fn into_iter(self) -> slice::IterMut<'a, T>;
// For vec, IntoIter takes value.

// Further encapsulate inner data structure using iter types.
// vec does not impl Iterator but impl IntoIterator for T, &T, &mut T
// using own internal Iter, IterMut and IntoIter objects to impl
// Iterator instead of directly.

// In stable, RefCell does not provide a way to get plain ref to T.
// Both Ref and RefMut wrappers do provide leak() in nightly.
// But this method does not use that.
// unsafe is used in next()
struct Iter<'a, T> {
    next: Option<NodeRef<T>>,
    data: Option<NodeData<T>>,
    phantom: PhantomData<&'a T>,
}
struct IterMut<'a, T> {
    next: Option<NodeRef<T>>,
    data: Option<NodeData<T>>,
    phantom: PhantomData<&'a T>,
}
struct IntoIter<T> {
    next: Option<NodeRef<T>>,
}

// IntoIterator for loop
impl<'a, T> IntoIterator for &'a LinkedList<T> {
    type IntoIter = Iter<'a, T>;
    type Item = &'a T;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
impl<'a, T> IntoIterator for &'a mut LinkedList<T> {
    type IntoIter = IterMut<'a, T>;
    type Item = &'a mut T;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}
impl<T> IntoIterator for LinkedList<T> {
    type IntoIter = IntoIter<T>;
    type Item = T;

    fn into_iter(self) -> Self::IntoIter {
        self.into_iter()
    }
}

#[cfg(test)]
mod test {
    use super::LinkedList;

    #[test]
    fn test_linkedlist_iter() {
        let mut linked_list = LinkedList::new("first");

        linked_list.append("second");
        linked_list.append("third");
        linked_list.append("fourth");

        // linked_list.for_each(|ptr| println!("data = {}", ptr.borrow().data.borrow()));

        linked_list
            .iter()
            .for_each(|data| println!("data = {}", data));

        linked_list
            .iter_mut()
            .for_each(|data| println!("data = {}", data));

        for data in &linked_list {
            println!("data: {}", data);
        }

        linked_list
            .into_iter()
            .for_each(|data| println!("data = {}", data));
    }
}

// Usage
fn usage() -> std::io::Result<()> {
    let vec = vec![1, 2, 3, 4];
    println!("{:?}", vec);
    let vec: Vec<_> = vec.iter().map(|v| v.to_string()).collect();
    println!("{:?}", vec);

    let vec_varied = ["duck", "1", "2", "goose", "3", "4"];
    // flat_map flattens the Result of parse()
    // partition handles each Result as Ok and Err
    let (ok, fail): (Vec<_>, Vec<_>) = vec_varied
        .iter()
        .map(|v| v.parse::<i32>())
        .partition(Result::is_ok);
    println!("ok={:?}", ok);
    println!("fail={:?}", fail);

    // To get inner value:
    let successes: Vec<_> = ok.into_iter().map(Result::unwrap).collect();
    let failures: Vec<_> = fail.into_iter().map(Result::unwrap_err).collect();
    println!("successses={:?}", successes);
    println!("failures={:?}", failures);

    // Enumerate
    let popular_dog_breeds = vec![
        "Labrador",
        "French Bulldog",
        "Golden Retriever",
        "German Shepherd",
        "Poodle",
        "Bulldog",
        "Beagle",
        "Rottweiler",
        "Pointer",
        "Dachshund",
    ];
    let popular_dog_breeds_copy = popular_dog_breeds.clone();

    let ranked_breeds: Vec<_> = popular_dog_breeds.into_iter().enumerate().collect();
    println!("{:?}", ranked_breeds);

    let ranked_breeds: Vec<_> = popular_dog_breeds_copy
        .into_iter()
        .enumerate()
        .map(|(idx, breed)| (idx + 1, breed))
        // .rev() count down instead of up
        .collect();

    // Some methods
    let numbers = [1, 2, 3];
    let words = ["one", "two", "three"];
    let zipped: Vec<_> = numbers.iter().zip(words.iter()).collect();
    println!("{:?}", zipped); // [(1, "word"), ...]

    // Parse a log file
    let file_path = "log.txt";
    let file = File::open(file_path)?;

    let reader = BufReader::new(file);

    let log_entries: Vec<LogEntry> = reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() == 3 {
                Some(LogEntry::new(parts[0], parts[1], parts[2]))
            } else {
                None
            }
        })
        .collect();

    let user_access_count: HashMap<&str, usize> = log_entries
        .iter()
        .map(|entry| entry.username.as_str())
        .fold(HashMap::new(), |mut acc, username| {
            *acc.entry(username).or_insert(0) += 1;
            acc
        });

    for (username, count) in user_access_count {
        println!("User: {}, Access count: {}", username, count);
    }

    // Count charaters from string array.
    let names = ["Jane", "Jill", "Jack", "John"];
    let total_bytes = names.iter().map(|name| name.len()).sum::<usize>();
    // Take one element.
    let player_scores = [("Jack", 20), ("Jane", 23), ("Jill", 18), ("John", 19)];

    let players = player_scores
        .iter()
        .map(|(player, _score)| player)
        .collect::<Vec<_>>();

    // Order inplace with mut
    let mut teams = [
        [("Jack", 20), ("Jane", 23), ("Jill", 18), ("John", 19)],
        [("Bill", 17), ("Brenda", 16), ("Brad", 18), ("Barbara", 17)],
    ];

    let teams_in_score_order = teams
        .iter_mut()
        .map(|team| {
            team.sort_by(|&a, &b| a.1.cmp(&b.1).reverse());
            team
        })
        .collect::<Vec<_>>();

    // Special clone only needed elements with take().
    let efficient_take = ["Jill", "Jack", "Jane", "John"];
    let efficient_taken = efficient_take.iter().cloned().take(2).collect::<Vec<_>>();

    Ok(())
}

#[derive(Debug)]
struct LogEntry {
    timestamp: String,
    username: String,
    action: String,
}

impl LogEntry {
    fn new(timestamp: &str, username: &str, action: &str) -> Self {
        LogEntry {
            timestamp: timestamp.to_string(),
            username: username.to_string(),
            action: action.to_string(),
        }
    }
}
