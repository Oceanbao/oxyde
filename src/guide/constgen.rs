#![allow(dead_code)]

use std::{marker::PhantomData, ops::Deref};

struct Buffer<T, const LENGTH: usize> {
    buf: [T; LENGTH],
}

// Create a Buffer from fixed array of [T; LENGTH] by MOVE
// array into the struct, but not for any other type.
// Useful if working with Buffer over raw arrays.
impl<T, const LENGTH: usize> From<[T; LENGTH]> for Buffer<T, LENGTH> {
    fn from(value: [T; LENGTH]) -> Self {
        Buffer { buf: value }
    }
}

// To impl traits for external crate types
// 1) wrapper structs
// 2) using Deref trait
struct WrapperVec<T>(Vec<T>);

// To "pass through" wrapper and use Vec's methods,
// impl Deref for wrapper, compiler auto-deref wrapper
// when call methods that don't exist.
impl<T> Deref for WrapperVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        // WrapperVec is effectively a tuple.
        &self.0
    }
}

// Limitation: cannot use methods taking `self` by value, e.g. into_iter()
impl<T> WrapperVec<T> {
    fn into_iter(self) -> std::vec::IntoIter<T> {
        self.0.into_iter()
    }
}

// Blanket traits
// Concrete for some param, but generics for others.
// impl<T: Display> ToString for T
// It depends on Display being impl for T, then ToString will
// also auto provided with to_string()
//
// trait Blanket {}
// impl<T> Blanket for T {}

// Blanket trait to convert from Vec<T> into a Buffer
impl<T: Default + Copy, const LENGTH: usize> From<Vec<T>> for Buffer<T, LENGTH> {
    fn from(v: Vec<T>) -> Self {
        assert_eq!(LENGTH, v.len());
        let mut ret = Self {
            buf: [T::default(); LENGTH],
        };
        // memcpy() requires source and target same length
        ret.buf.copy_from_slice(&v);
        ret
    }
}

// Full-featured marker trait
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct KitchenSink;

trait FullFeatured {}

impl<T> FullFeatured for T where
    T: Clone + Copy + std::fmt::Debug + Default + std::hash::Hash + Ord + PartialEq + PartialOrd
{
}

#[derive(Debug)]
struct Container<T: FullFeatured> {
    t: T,
}

// Struct tagging - empty structs or unit structs to tag
// a generic type by including tag as unused type param.

#[derive(Default)]
struct On;
#[derive(Default)]
struct Off;

// let bulb = LightBulb<Off> { ... }

// state transition checking using compiler by using
// struct tag instead of value or variable.

trait BulbState {} // marker trait

// trait bound for State to be type providing BulbState trait
#[derive(Default)]
struct LightBulb<State: BulbState> {
    phantom: PhantomData<State>,
}

// marker trait impl on each
impl BulbState for On {}
impl BulbState for Off {}

// Extra useful when using type state to create methods
// e.g. transition between on and off states
impl LightBulb<On> {
    fn turn_off(self) -> LightBulb<Off> {
        LightBulb::<Off>::default()
    }
    fn state(&self) -> &str {
        "on"
    }
}
impl LightBulb<Off> {
    fn turn_on(self) -> LightBulb<On> {
        LightBulb::<On>::default()
    }
    fn state(&self) -> &str {
        "off"
    }
}

// Custom Indexing of array.
// Target is a collection type, i.e. [u32; 17]
trait IsValidIndex<Target> {
    const RESULT: ();
}

struct CustomIndex<const I: usize>;

impl<T, const I: usize, const N: usize> IsValidIndex<[T; N]> for CustomIndex<I> {
    const RESULT: () = assert!(N > I, "Index is out of bounds!");
}

use std::ops::Index;

impl<T, const N: usize, const I: usize> Index<CustomIndex<I>> for [T; N] {
    type Output = T;

    fn index(&self, _: CustomIndex<I>) -> &Self::Output {
        let _ = <CustomIndex<I> as IsValidIndex<Self>>::RESULT;
        unsafe { &*(self.as_ptr().add(I) as *const T) }
    }
}

// Custom Indexing slice.
trait IsValidRangeIndex<Target> {
    const RESULT: ();
}

pub struct CustomRangeIndex<const START: usize, const LENGTH: usize>;

impl<T, const START: usize, const LENGTH: usize, const N: usize> IsValidRangeIndex<[T; N]>
    for CustomRangeIndex<START, LENGTH>
{
    const RESULT: () = assert!(N >= START + LENGTH, "Ending index is out of bounds!");
}

impl<T, const START: usize, const LENGTH: usize, const N: usize>
    Index<CustomRangeIndex<START, LENGTH>> for [T; N]
{
    type Output = [T; LENGTH];

    fn index(&self, _: CustomRangeIndex<START, LENGTH>) -> &Self::Output {
        let _ = <CustomRangeIndex<START, LENGTH> as IsValidRangeIndex<Self>>::RESULT;
        unsafe { &*(self.as_ptr().add(START) as *const [T; LENGTH]) }
    }
}

fn run() {
    let lightbulb = LightBulb::<Off>::default();
    println!("Bulb is {}", lightbulb.state());
    // `self` consumed because cannot change type param on generic struct.
    let lightbulb = lightbulb.turn_on();
    println!("Bulb is {}", lightbulb.state());

    let x = &[1u8, 2, 4, 8, 16, 32];
    let _ = x[CustomIndex::<8>];

    let x = &[0x01, 0x03, 0x00, 0x00, 0x88, 0x77, 0x66, 0x55];
    let y = u16::from_le_bytes(x[CustomRangeIndex::<4, 2>]);
    assert_eq!(y, 0x7788);
}
