#![allow(dead_code)]

use std::fs::File;
// `str` - a stack UTF-8 string for read only.
// `String` - a heap fat-pointer for read and write
// - always borrow `String` as `&str`, which is the LCD (lowest common denomiator).
// - String is just Vec of UTF-8 char and str just slice of which.
// `&str` immutable string ref, pointer to either borrowed str or String, plus length.
// - String can be moved, but str cannot.
pub fn which_string() {
    // Write?
    let writable_string = String::from("writable string");
    // Read?
    let readable_string = "readonly string";

    // Real diff btw &'static str and &str is that
    // while a String can be borrowed as &str, String can never
    // be borrowed as &'static str since lifetime of String shorter than program.
    println!("{} - {}", writable_string, readable_string);
}

// Array is fixed-length sequence of values.
// Slice a sequence of values with arbitrary length.
// Can recursively deconstruct slices into non-overlapping sub-slices.
// 1.51 const generics to define generic arrays of arbitrary length, but only at CT.
fn which_sequence() {
    let array = [0u8; 64];
    let slice: &[u8] = &array;

    let (first_half, second_half) = slice.split_at(32);
    println!(
        "first_half.len()={} second_half.len()={}",
        first_half.len(),
        second_half.len()
    );

    // Optim methods on slice.
    // slice.copy_from_slice();
    // slice.fill();
    // slice.fill_with();

    // as_slice(&self) -> &[T] { self }
    // This works due to `Deref` (its mutable sibling `DerefMut`) that may be used
    // by compiler to coerce types.
    // NOTE: slice cannot be resized and the length is provided to slice at time of deref.
    // If taking slice of vector, resized the vector, the slice size would not change.
    //
    // let mut vec = vec![1, 2, 3];
    // let vec_slice = vec.as_slice(); // read borrow
    // vec.resize(10, 0); // write borrow
    // println!("{}", vec_slice[0]); // another read borrow fails

    // VecDeque - double-ended queue resizable
    // LinkedList
    // HashMap
    // BTreeMap
    // HashSet
    // BTreeSet
    // BinaryHeap - priority queue, impl with a binary heap, using Vec

    // use metrohash::MetroBuildHasher;
    // use std::collections::HashMap;

    // let mut map = HashMap::<String, String, MetroBuildHasher>::default();
    // map.insert("hello?".into(), "Hello!".into());
    //
    // Into trait to cask &str to String for owning.

    // Custom hashable types
    #[derive(Hash, Eq, PartialEq, Debug)]
    struct CompoundKey {
        name: String,
        value: i32,
    }
}

fn all_types() {
    // Primitives - strings, arrays, tuples, integrals
    // Struct
    // Enum
    // Alias
    let value = 0u8;
    println!("value={}, length={}", value, std::mem::size_of_val(&value));
    let value = 0b1u16;
    println!("value={}, length={}", value, std::mem::size_of_val(&value));
    let value = 0o2u32;
    println!("value={}, length={}", value, std::mem::size_of_val(&value));
    let value = 0x3u64;
    println!("value={}, length={}", value, std::mem::size_of_val(&value));
    let value = 4u128;
    println!("value={}, length={}", value, std::mem::size_of_val(&value));

    println!("Binary (base 2) 0b1111_1111={}", 0b1111_1111);
    println!("Octal (base 8) 0o1111_1111={}", 0o1111_1111);
    println!("Decimal (base 10)   1111_1111={}", 1111_1111);
    println!("Hexadecimal (base 16) 0x1111_1111={}", 0x1111_1111);
    println!("Byte literal b'A'={}", b'A');

    // Empty struct
    struct EmptyStruct;
    struct TupleStruct(String);
    pub struct MixedVisiableStruct {
        pub name: String,
        pub(crate) value: String,
        pub(super) number: i32,
    }
    #[derive(Debug, Clone, Default)]
    struct TypicalStruct {
        name: String,
        age: i32,
    }
    let typical_struct = TypicalStruct::default();
    println!("{:#?}", typical_struct);
    println!("{}", typical_struct.name);
    println!("{}", typical_struct.age);

    impl TypicalStruct {
        fn grow(&mut self) {
            self.age += 1;
        }
    }

    #[derive(Debug)]
    enum JapaneseDogBreeds {
        AkitaKen,
        HokkaidoInu,
        KaiKen,
        KishuInu,
        ShibaInu,
        ShikokuKen,
    }

    impl From<u32> for JapaneseDogBreeds {
        fn from(other: u32) -> Self {
            match other {
                other if JapaneseDogBreeds::AkitaKen as u32 == other => JapaneseDogBreeds::AkitaKen,
                other if JapaneseDogBreeds::HokkaidoInu as u32 == other => {
                    JapaneseDogBreeds::HokkaidoInu
                }
                _ => panic!("Unknown breed!"),
            }
        }
    }

    enum EnumTypes {
        NamedType,
        String,
        NamedString(String),
        StructLike { name: String },
        TupleLike(String, i32),
    }

    // Aliasing
    pub(crate) type MyMap = std::collections::HashMap<String, TypicalStruct>;

    // Example of encapsulation.
    // Stack-alloc key type
    // pub type Key = StackByteArray<CRYPTO_KDF_KEYBYTES>;
}

#[derive(Debug)]
struct MyError {
    message: String,
}

// To allow ? to convert into MyError from the origin error.
impl From<std::io::Error> for MyError {
    fn from(other: std::io::Error) -> Self {
        Self {
            message: other.to_string(),
        }
    }
}

fn handle_error(name: &str) -> Result<String, MyError> {
    use std::io::prelude::Read;

    let mut file = File::open(name)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    println!("{}", StringWrapper::from("hello from my string").0);

    Ok(contents)
}

// General rule: only need to impl From, almost never Into.
struct StringWrapper(String);

impl From<&str> for StringWrapper {
    fn from(other: &str) -> Self {
        Self(other.into())
    }
}

// TryFrom - all but for fallable conversion -> Result
