#![allow(dead_code)]

macro_rules! print_what_it_is {
    () => {
        println!("A macro with no arg");
    };
    ($e:expr) => {
        println!("A macro with an expression");
    };
    ($s:stmt) => {
        println!("A macro with a statement");
    };
    ($e:expr, $s:stmt) => {
        println!("An expression followed by a statement");
    };
}

// nightly debug macro flag
// #![feature(trace_macros)]
//
// trace_macros!(true);
// special_println("hello");
// trace_macros!(false);
macro_rules! special_println {
    // $arg is named identifier for args matching this rule.
    // match on `tt` (token trees) - a single identifier, or a sequence of token trees.
    // match rule is within parenthese i.e. $(...) denoting repetition rule.
    // last char * telling compiler these args can repeat any number of times
    // regex + for 1 or more, * for any number of matches, ? for 1 or 0 matches.
    ($($arg:tt)*) => {
        println!("Prefix: {}", $($arg)*);
    };
}

macro_rules! var_print {
    // matches on comma-sep list of identifiers, `$($v:ident),*`
    // 2 separate inner expr of $v, one to produce first arg, the other to pass the remainders
    // first arg is formatting, as name=value
    // stringify! macro convert token to string
    // concat! macro concatenate strings into one
    // first concat! expansion to concat each arg with "={:?}"
    // separate expansion is $($v),* and passed as second arg
    ($($v:ident),*) => {
        println!(concat!($(concat!(stringify!($v),"={:?} ")),*), $($v),*)
    };
}

// DRY
trait Dog {
    fn name(&self) -> &String;
    fn age(&self) -> i32;
    fn breed(&self) -> &String;
}

macro_rules! dog_struct {
    ($breed:ident) => {
        struct $breed {
            name: String,
            age: i32,
            breed: String,
        }
        impl $breed {
            fn new(name: &str, age: i32) -> Self {
                Self {
                    name: name.into(),
                    age,
                    breed: stringify!($breed).into(),
                }
            }
        }
        impl Dog for $breed {
            fn name(&self) -> &String {
                &self.name
            }
            fn age(&self) -> i32 {
                self.age
            }
            fn breed(&self) -> &String {
                &self.breed
            }
        }
    };
}

// Emulating optional args
// - Extending with traits
// - Using macros to match args
// - Wrapping args with Option

// Emulating optional arg with traits
struct Container {
    name: String,
}

trait First {
    fn name(&self) {}
}
trait Second {
    fn name(&self, _: bool) {}
}
impl First for Container {
    fn name(&self) {}
}
impl Second for Container {
    fn name(&self, _: bool) {}
}
// Problem: container.name() err because of ambiguity of same name
// methods. Also problem for diff args in each trait.
// Solution: trait bound in standalone function.
fn get_name_first<T: First>(t: &T) {
    t.name()
}
fn get_name_second<T: Second>(t: &T) {
    t.name(true)
}

// Idea: func and method names cannot overload, even if arg differs
// trait may be impl with conflicting methods for a type
// generics can specify trait bounds to disambiguate conflicting methods
// So: except base types String and numerics, prefer accepting func params as generics!

fn run() {
    print_what_it_is!();
    print_what_it_is!({});
    print_what_it_is!(;);
    print_what_it_is!({}, ;);

    special_println!("special prefix");

    let counter = 7;
    let gauge = 3.13;
    let name = "Peter";
    var_print!(counter, gauge, name);

    dog_struct!(Labrador);
    dog_struct!(Golden);
    dog_struct!(Poodle);

    let peter = Poodle::new("Peter", 7);
    println!(
        "{} is a {} of age {}",
        peter.name(),
        peter.breed(),
        peter.age()
    );

    let container = Container {
        name: "Henry".into(),
    };

    get_name_first(&container);
    get_name_second(&container);
}

// mini-DSL check out lazy_static
