pub trait Quicksort {
    fn quicksort(&mut self) {}
}

impl<T: std::cmp::PartialOrd + Clone> Quicksort for [T] {
    fn quicksort(&mut self) {
        _quicksort(self);
    }
}

pub fn _quicksort<T: std::cmp::PartialOrd + Clone>(slice: &mut [T]) {
    if slice.len() < 2 {
        return;
    }
    let (left, right) = partition(slice);
    _quicksort(left);
    _quicksort(right);
}

pub fn partition<T: std::cmp::PartialOrd + Clone>(slice: &mut [T]) -> (&mut [T], &mut [T]) {
    let pivot_value = slice[slice.len() - 1].clone();
    let mut pivot_index = 0;
    for i in 0..slice.len() {
        if slice[i] <= pivot_value {
            slice.swap(i, pivot_index);
            pivot_index += 1;
        }
    }
    if pivot_index < slice.len() - 1 {
        slice.swap(pivot_index, slice.len() - 1);
    }

    slice.split_at_mut(pivot_index - 1)
}
