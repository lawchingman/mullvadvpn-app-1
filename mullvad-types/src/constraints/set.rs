//! A limited variant of Sets.

// TODO(markus): Implement `intersection` on `Set` instead?
pub trait Set<T> {
    fn is_subset(&self, other: &T) -> bool;
}
