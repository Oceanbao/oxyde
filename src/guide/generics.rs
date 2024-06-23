#![allow(dead_code, unused_variables)]

use std::marker::PhantomData;

struct Container<T> {
    value: T,
}

impl<T> Container<T> {
    fn new(value: T) -> Self {
        Self { value }
    }
}

fn use_container() {
    let short_alt_ambiguous = Container::<Option<String>>::new(None);
}

// Unused generic type
struct Dog<Breed> {
    name: String,
    // a phantom field to let compiler know that Breed is needed
    // but only care the value at CT and thus not stored in struct.
    breed: PhantomData<Breed>,
}

struct Labrador {}
struct Retriever {}
struct Poodle {}
struct Dachshunds {}

fn use_dog() {
    // Marker pattern - CT optim or specialised types.
    let poodle: Dog<Poodle> = Dog {
        name: "Jeffrey".into(),
        breed: PhantomData,
    };
}

// Using type but no actual value stored as state.
impl Dog<Labrador> {
    fn breed_name(&self) -> &'static str {
        "labrador"
    }
}
impl Dog<Retriever> {
    fn breed_name(&self) -> &'static str {
        "retriever"
    }
}
impl Dog<Poodle> {
    fn breed_name(&self) -> &'static str {
        "poodle"
    }
}
impl Dog<Dachshunds> {
    fn breed_name(&self) -> &'static str {
        "dachshund"
    }
}

// Handy conversion between Result and Option
// result.ok() -> Option<T>
// result.err() -> Option<E>
// E.map_err() -> map error to a diff type
// Option<T>.ok_or() -> Result<T, E>
