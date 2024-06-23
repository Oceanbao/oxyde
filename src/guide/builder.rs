#![allow(dead_code)]

#[derive(Debug)]
struct Bicycle {
    make: String,
    model: String,
    size: i32,
    colour: String,
}

// impl Bicycle {
//     fn make(&self) -> &String {
//         &self.make
//     }
//     fn model(&self) -> &String {
//         &self.model
//     }
//     fn size(&self) -> i32 {
//         self.size
//     }
//     fn colour(&self) -> &String {
//         &self.colour
//     }
// }

struct BicycleBuilder {
    bicycle: Bicycle,
}

impl BicycleBuilder {
    fn new() -> Self {
        Self {
            bicycle: Bicycle {
                make: String::new(),
                model: String::new(),
                size: 0,
                colour: String::new(),
            },
        }
    }

    // fn with_make(&mut self, make: &str) {
    //     self.bicycle.make = make.into()
    // }

    // fn with_model(&mut self, model: &str) {
    //     self.bicycle.model = model.into()
    // }

    // fn with_size(&mut self, size: i32) {
    //     self.bicycle.size = size
    // }

    // fn with_colour(&mut self, colour: &str) {
    //     self.bicycle.colour = colour.into()
    // }

    fn build(self) -> Bicycle {
        self.bicycle
    }
}

// Enhancing builder with trait
trait Builder<T> {
    fn new() -> Self;
    fn build(self) -> T;
}

impl Builder<Bicycle> for BicycleBuilder {
    fn new() -> Self {
        Self {
            bicycle: Bicycle {
                make: String::new(),
                model: String::new(),
                size: 0,
                colour: String::new(),
            },
        }
    }

    fn build(self) -> Bicycle {
        self.bicycle
    }
}

// This trait gives us get an instance of builder
trait Buildable<Target, B: Builder<Target>> {
    fn builder() -> B;
}

impl Buildable<Bicycle, BicycleBuilder> for Bicycle {
    fn builder() -> BicycleBuilder {
        BicycleBuilder::new()
    }
}

fn run() {
    // let mut bicycle_builder = BicycleBuilder::new();
    // bicycle_builder.with_make("Buffy");
    // bicycle_builder.with_model("Radio");
    // bicycle_builder.with_size(46);
    // bicycle_builder.with_colour("red");
    // let bicycle = bicycle_builder.build();
    // println!("My new bike: {:?}", bicycle);

    // let mut bicycle_builder_new = Bicycle::builder();
    // bicycle_builder_new.with_make("Buffy");
    // bicycle_builder_new.with_model("Radio");
    // bicycle_builder_new.with_size(46);
    // bicycle_builder_new.with_colour("red");
    // let bicycle_new = bicycle_builder_new.build();
    // println!("My new bicycle: {:?}", bicycle_new);

    let bicycle = Bicycle::builder()
        .with_make("Trek")
        .with_model("Madone")
        .with_size(52)
        .with_colour("purple")
        .build();
    println!("{:?}", bicycle);
}

// Enhancing builder with macros
// Updated with chaining (return self)
macro_rules! with_str {
    ($name:ident, $func:ident) => {
        // NOTE: use of spread `..` MOVE original
        // NOTE: `self` consumes self and make new one.
        fn $func(self, $name: &str) -> Self {
            Self {
                bicycle: Bicycle {
                    $name: $name.into(),
                    ..self.bicycle
                },
            }
        }
    };
}

macro_rules! with {
    ($name:ident, $func:ident, $type:ty) => {
        fn $func(self, $name: $type) -> Self {
            Self {
                bicycle: Bicycle {
                    $name,
                    ..self.bicycle
                },
            }
        }
    };
}

impl BicycleBuilder {
    with_str!(make, with_make);
    with_str!(make, with_model);
    with!(size, with_size, i32);
    with_str!(colour, with_colour);
}

macro_rules! accessor {
    ($name:ident, &$ret:ty) => {
        pub fn $name(&self) -> &$ret {
            &self.$name
        }
    };

    ($name:ident, $ret:ty) => {
        pub fn $name(&self) -> $ret {
            self.$name
        }
    };
}

impl Bicycle {
    accessor!(make, &String);
    accessor!(model, &String);
    accessor!(size, i32);
    accessor!(colour, &String);
}

// In prod, use `derive_builder` crate.
