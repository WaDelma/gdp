use std::{marker::PhantomData, ops::Deref};

/// Holds unique lifetime which is used as a name
#[derive(Clone)]
pub struct Name<'name>(PhantomData<fn(&'name ()) -> &'name ()>);

/// Generates unique name
pub fn gen<'name>() -> Name<'name> {
    Name(PhantomData)
}

/// Arbitrary value named with unique name
#[derive(Clone)]
pub struct Named<'name, V>(Name<'name>, V);

impl<'name, V> Named<'name, V> {
    pub fn name(self) -> Name<'name> {
        self.0
    }
}

impl<'name, V> Deref for Named<'name, V> {
    type Target = V;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

// Allows running closure in which given value is named with unique name
pub fn name<V, T>(value: V, f: impl for<'name> FnOnce(Named<'name, V>) -> T) -> T {
    f(Named(gen(), value))
}
