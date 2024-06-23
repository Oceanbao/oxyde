#![allow(dead_code, unused_variables)]

use core::fmt;
use std::{cell::RefCell, rc::Rc};

fn prefer_result_option_transformation_over_match(username: &str) -> Result<String, String> {
    // not Err(e) => return Err(format!("Failed to open {:?}", e))
    let f =
        std::fs::File::open("/etc/passwd").map_err(|e| format!("failed to open passwd {:?}", e))?;

    Ok("Ok".to_owned())
}

// Exception: shared reference &Option<T>.unwrap() cannot move T out because Option !: Copy
// Option<T>.as_ref().unwrap()

fn newtype_pattern() {
    struct PoundForceSecond(f64);
    // instead of type
    fn thruster_impulse(direction: &str) -> PoundForceSecond {
        PoundForceSecond(42.0)
    }
    struct NewtonSeconds(f64);
    fn update_trajectory(force: NewtonSeconds) {}

    impl From<PoundForceSecond> for NewtonSeconds {
        fn from(value: PoundForceSecond) -> Self {
            NewtonSeconds(4.448222 * value.0)
        }
    }
    let thruster_force: PoundForceSecond = thruster_impulse("direction");
    update_trajectory(thruster_force.into());

    // Another to make simple bool type (or alias) more semantic.
    struct DoubleSided(bool);
    struct ColorOutput(bool);
    fn print_page(side: DoubleSided, color: ColorOutput) {}
    print_page(DoubleSided(true), ColorOutput(false));

    // Bypassing Orphan rule by newtype
    struct MyString(String);
    impl fmt::Display for MyString {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "<String>")
        }
    }
    // Limitation, 1) always use .0
    // 2) inner type trait is lost, lots of #[derive(Debug, Copy, Clone, Eq, PartialEq, Ord,
    //    PartialOrd)]
    // 3) for more sophisticated traits, need to forward
    // fn fmt(...) self.0.fmt(f)
}

// Builder `derive_builder` for reducing boilterplate.

fn king_reference() {
    // &T can be passed by &Box<T> because it impl Deref<Target = T>
    // that Box<T>.deref() -> Target
    // "it's coercion allowing various fat pointers to behave like normal ref"
    // NOTE: Deref cannot be generic over Target (hence associated type) due to
    // impossible to have > 1 Deref as it's implicit.
    //
    // This makes Deref diff from AsRef - which is generic over T (as_ref) that
    // a single container can support multiple Target: AsRef<Target> for T
    //
    // e.g. String impl Deref<Target = str> that &my_string can be coerced into &str
    // AND it also impl:
    // AsRef<[u8]> into &[u8]
    // AsRef<OsStr> into OS string
    // AsRef<Path> into filesystem path
    // AsRef<str> into &str (same as Deref)
    //
    // Two fat pointers: slices and trait objects.
    //
    // NOTE: steps involved for &vec[1..3]
    // - 1..3 is range expression -> Range<usize>
    // - Range impl SliceIndex<T> indexing ops on slices for T (Output = [T])
    // - vec[] is indexing expression -> Index trait .index() together with a deref (*vec.index())
    // (Vec<T> impl Index<I> where I: SliceIndex<[u64]> which works as Range<usize> impl
    // SliceIndex<[T]> for any T)
    // - &vec[1..3] undoes the deref into &[u64]
    //
    // Pointer Traits - dealing with references.
    //
    // Borrow(Mut) same signature as AsRef/AsMut BUT:
    //
    // Rust has blanket impl of (for &T) both AsRef and Borrow (and mut).
    // BUT Borrow also has blanket impl for non-ref types: impl<T> Borrow<T> for T
    fn add_four<T: std::borrow::Borrow<i32>>(v: T) -> i32 {
        v.borrow() + 4
    }
    // Both &T and T works for Borrow
    assert_eq!(add_four(&2), 6);
    assert_eq!(add_four(2), 6);
    // e.g. HashMap::get uses Borrow to allow handy retrieval of entires given key by T or &T

    // ToOwned - built on top of Borrow with .to_owned() -> a new owned item of T.
    // This is a generalisation of Clone, which requires &T, whereas ToOwned instead copes with
    // T impl Borrow.
    //
    // So?
    //
    // Ways for handling both &T and T in a UNIFIED way:
    //
    // - func takes &T can take T: Borrow, so can take move and ref
    // - func takes T can take T: ToOwned, so can take move and ref (&T passed replicated into
    // locally owned T)
    //
    // Rc<T> impl all Pointer related trais acting like Box<T> in many ways.
    // Allow shared ownership! So possible leakage by cycle. Fix: Weak<T> that
    // holds non-owning &T
    let rc1: std::rc::Rc<u64> = std::rc::Rc::new(42); // heap: strong=2
    let rc2 = rc1.clone(); // heap: strong=2
    let wk = std::rc::Rc::downgrade(&rc1); // heap: weak=1

    // T is dropped when strong == 0, BUT boopkeeping drops only when weak=0
    //
    // only mutate via get_mut() EXCLUSIVE! (no other extant Rc or Weak copies)
    //
    // RefCell<T> relaxes that T can mutate only by its owner OR
    // by code that holds the (only) mutable ref to T.
    // mutable even with &self input
    // BUT: extra storage isize to track current borrows and borrow check at RT.
    let rfc: std::cell::RefCell<u64> = std::cell::RefCell::new(42);
    let b1 = rfc.borrow();
    let b2 = rfc.borrow();

    // RT checks means 2 options:
    // - accept borrow may fail, and handles Result from try_borrow[_mut]
    // - panic if fails on borrow[_mut]
    // (this means RefCell impl none of normal pointer traits and using Ref RefMut)
    //
    // If T: Copy (bit-wise), then Cell<T> allows interior mutation with less overhead by
    // .get(&self) coipes out T and .set(&self, val) copies in a new value.
    // Cell is used internally by Rc and RefCell, for shared tracking of counters that can
    // be mutated without a &mut self
    //
    // Thread-safe version: Arc and Mutex that .lock() -> MutexGuard<T> which impl Deref[Mut]
    // If more read `RwLock` but panic if > 1 writer!
    let shared_as_whole = Rc::new(RefCell::new(vec![1, 2, 3]));
    let shared_part = Rc::new(vec![RefCell::new(1), RefCell::new(2), RefCell::new(3)]);
}

fn iterator_is_king() -> Result<(), Box<dyn std::error::Error>> {
    let values: Vec<u64> = Vec::from_iter(0..100);
    let even_sum_squared: u64 = values
        .iter()
        .filter(|x| *x % 2 == 0)
        .take(5)
        .map(|x| x * x)
        .sum();

    // Flow:
    // - initial source, from an instance of T impl one of iterator traits.
    // - sequence of iterator transforms
    // - final consumer method to combine results

    // Iterator Traits
    // Iterator .next()
    // IntoIterator .into_iter() for collections 'iterables' (Self) -> Iterator
    // NOTE: to disambiguates, do not impl Copy for .into_iter() items.
    //
    // Convention to impl .iter() and iter_mut()
    //
    // take(n)
    // skip(n)
    // step_by(n)
    // chain(other)
    // cycle() T: Clone
    // rev() T: DoubleEndedIterator .next_back()
    //
    // cloned() useful for &Item where T: Clone
    // copied() same but T: Copy and likely to be faster if so
    // enumerate() -> usize, Item
    // zip(it)
    //
    // filter(|item| { ... })
    // take_while() emits initial subrange based on predicate, mirror of skip_while
    // skip_while() emits final subrange
    //
    // flatten() T: Iterator
    let to_flatten_options = &[Some(1), None, Some(2)];
    let a: Vec<_> = to_flatten_options.iter().flatten().collect();
    // Useful to handle a stream of Option/Result to extract valid values, IGNORING the rest.
    //
    // Consuming:
    //
    // .for_each(|value| "closure needs mutable ref to state elsewhere")
    // sum()
    // product()
    // min() T: Ord
    // max()
    // min_by(f)
    // max_by(f)
    // reduce(f) for Item
    // fold(f) general reduce() for arbitrary type
    // scan(init, f)
    // find(p)
    // position(p)
    // nth(n)
    // any(p)
    // all(p)
    //
    // try_for_each(f)
    // try_fold(f)
    // try_find(f)
    //
    // collect() T: FromIterator
    // (impl for std collection types, Vec, HashMap, BTreeSet, ...) hence the need
    // to explicitly annotate T, else compile confused.
    let myvec: std::collections::HashSet<_> = (0..10).into_iter().filter(|x| x % 2 == 0).collect();

    // unzip()
    // partition(p)
    //
    // Best Practice to handle Results collection
    // let result: Vec<Result<u8, _>> = inputs.into_iter().map(|v| <u8>::try_from(v)).collect();
    let inputs: Vec<i64> = vec![0, 1, 2, 3, 4, 512];
    let results: Vec<u8> = inputs
        .into_iter()
        .map(<u8>::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    // - if encouters error value, error value is emitted to caller and stops
    // - else, remainder of code can work with sensible values.
    Ok(())
}
