#![allow(dead_code)]

// TRAIT Subject
// .attach(Observer)
// .detach(OBserver)
// .update()
//
// TRAIT Observer
// .observe(Subject)

// Observer - objects that want to observe others
// Observable - objects allowing others to observe them

use std::{sync::Arc, sync::Weak};

trait Observer {
    type Subject;

    fn observe(&self, subject: &Self::Subject);
}

trait Observable {
    type Observer;

    fn update(&self);
    fn attach(&mut self, observer: Self::Observer);
    fn detach(&mut self, observer: Self::Observer);
}

struct Subject {
    // weak pointer holding Observer
    observers: Vec<Weak<dyn Observer<Subject = Self>>>,
    state: String,
}

impl Observable for Subject {
    // NOTE: Arc<dyn T> gives more flexibility
    // 1) can store pointers as Weak pointers - when they scope out we can ignore, instead of
    //    keeping them alive.
    // 2) Arc also allows shared ownership (subject shouldn't OWN observers)
    type Observer = Arc<dyn Observer<Subject = Self>>;

    fn update(&self) {
        self.observers
            .iter()
            // upgrade() on Weak -> Option, hence flat_map and remove None cases
            .flat_map(|o| o.upgrade())
            // call observe on each valid observer
            .for_each(|o| o.observe(self));
    }

    fn attach(&mut self, observer: Self::Observer) {
        // When a new observer added, downgrade it from Arc to Weak pointer
        self.observers.push(Arc::downgrade(&observer));
    }

    fn detach(&mut self, observer: Self::Observer) {
        // Must `ptr_eq` to find matching object
        // Vec::retain() filters out all objects matching the pointer passed
        self.observers
            .retain(|f| !f.ptr_eq(&Arc::downgrade(&observer)));
    }
}

impl Subject {
    fn new(state: &str) -> Self {
        Self {
            observers: vec![],
            state: state.into(),
        }
    }

    fn state(&self) -> &str {
        self.state.as_ref()
    }
}

struct ObserverA {
    name: String,
}

impl ObserverA {
    fn new(name: &str) -> Arc<Self> {
        Arc::new(Self { name: name.into() })
    }
}

impl Observer for ObserverA {
    type Subject = Subject;

    fn observe(&self, subject: &Self::Subject) {
        println!(
            "observed subject with state={:?} in {}",
            subject.state(),
            self.name
        )
    }
}

fn run() {
    let mut subject = Subject::new("some subject state");

    let observer1 = ObserverA::new("observer1");
    let observer2 = ObserverA::new("observer2");

    // clone since it'd scope out when passed by value.
    subject.attach(observer1.clone());
    subject.attach(observer2.clone());

    // do sth...

    // Normally update() WITHIN subject whenever its state changes
    // to trigger our observers
    subject.update();
}
