#![allow(dead_code, unused_variables)]

fn run_lifetimes() {
    {
        let mut s: String = "Hello, world".to_string();

        let mut_ref = &mut s[..5];
        mut_ref.make_ascii_uppercase();

        // ok to create immut-ref to String
        let r: &str = &s;
        println!("s = {}", r);
    }

    // elision rule for &self method
    // &'a self -> &'a Output

    struct Item {
        contents: i32,
    }

    {
        let outer = Item { contents: 7 };
        {
            let inner = Item { contents: 8 };
            {
                // let min = smaller(&inner, &outer);
            } // min drops
        } // inner drops
    } // outer drops

    // If output lifetime unrelated to that of inputs, then no
    // need for those lifetimes to nest
    {
        // lifetime 'a
        let haystack = b"1234";
        let found = {
            // lifetime 'b
            let needle = b"234";
            // find(haystack, needle)
            b"456"
        }; // end of lifetime 'b
        println!("found={:?}", found); // `found` used within 'a, outside `b
    } // end of lifetime 'a

    // Simplest way to get sth with 'static is static keyword
    static ANSWER: Item = Item { contents: 42 };

    // Note returning created reference
    fn the_answer() -> &'static Item {
        &ANSWER
    }

    // NOTE: gotchas on `const` promoted to `static lifetime:
    // - no promotion if T has destructor or IM
    // - only the VALUE of const is guaranteed, not the pointer addr copied
    // Box is not 'static on heap, BUT .leak() converts to &mut T, no longer
    // owner so can never be dropped, satisfying 'static
    {
        let boxed = Box::new(Item { contents: 12 });

        let r: &'static Item = Box::leak(boxed);
    } // boxed not dropped here, as it was already moved into Box::leak()

    // Because `r` is now out of scope, the Item is leaked forever
    // This is safe Rust because `r` leaked can never be accessed.

    // Chain of lifetime and dropping out of scope
    // Eventually either linked to a stack value or 'static

    // NOTE: lifetime for DS is infectious: any containing DS using the type also has to tag a
    // lifetime.
    //
    // Also needed if DS holding slice types, as they are references.

    // Logical lifetimes
    // find_common_substring(a and b) need both (two references)
    // find_repeated_substring(a and b) only need one (same reference)

    // Prefer owning DS, if impossible, use smart pointers Rc etc.
}
