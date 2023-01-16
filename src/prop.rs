use super::proof::{axiom, Proof};

#[derive(Clone, Copy)]
pub struct True;
#[derive(Clone, Copy)]
pub struct False;
#[derive(Clone, Copy)]
pub struct And<P, Q>(P, Q);
#[derive(Clone, Copy)]
pub struct Or<P, Q>(P, Q);
#[derive(Clone, Copy)]
pub struct Not<P>(P);
pub struct Impl<P, Q>(P, Q);

// Truth is always provably true
pub fn t() -> Proof<True> {
    axiom()
}

impl<P> Proof<P> {
    // For any proposition it holds that both it and its negation cannot be true at the same time
    pub fn non_contra(self) -> Proof<Not<And<P, Not<P>>>> {
        axiom()
    }
}

/// Construct and from its parts
pub fn and<P, Q>(_: Proof<P>, _: Proof<Q>) -> Proof<And<P, Q>> {
    axiom()
}

/// Construct or from left value
pub fn or_l<P, Q>(_: Proof<P>) -> Proof<Or<P, Q>> {
    axiom()
}

/// Construct or from right value
pub fn or_r<P, Q>(_: Proof<Q>) -> Proof<Or<P, Q>> {
    axiom()
}

/// If we can prove Q from P, then we can lift this proof to the logic level.
pub fn implication<P, Q>(_: impl FnOnce(Proof<P>) -> Proof<Q>) -> Proof<Impl<P, Q>> {
    axiom()
}

/// If we can prove falsehood from P, then negation of P has to hold
pub fn intro_not<P>(_: impl FnOnce(Proof<P>) -> Proof<False>) -> Proof<Not<P>> {
    axiom()
}

impl<P, Q> Proof<And<P, Q>> {
    /// Extract the left component of and
    pub fn elim_l(self) -> Proof<P> {
        axiom()
    }
    /// Extract the right component of and
    pub fn elim_r(self) -> Proof<Q> {
        axiom()
    }
}

impl<P: Copy, Q: Copy> Proof<And<P, Q>> {
    /// Extract both components of and
    pub fn elim(self) -> (Proof<P>, Proof<Q>) {
        (self.elim_l(), self.elim_r())
    }
}

impl<P, Q> Proof<Or<P, Q>> {
    /// Elimination by case analysis: If we can prove a fact from both cases, we can prove from the or.
    ///
    /// *Note*: Because we don't know which of the `P` and `Q` holds at the runtime, given functions are not actually ran.
    pub fn elim<R>(self, _: impl FnOnce(Proof<P>) -> Proof<R>, _: impl FnOnce(Proof<Q>) -> Proof<R>) -> Proof<R> {
        axiom()
    }
}

impl<P, Q> Proof<Impl<P, Q>> {
    /// We can apply our implication like a function. Also known as modus ponens.
    pub fn elim(self, _: Proof<P>) -> Proof<Q> {
        axiom()
    }
}

impl Proof<False> {
    /// If we have proven falsehood, we are in contradiction and everything is true.
    pub fn absurd<P>(self) -> Proof<P> {
        axiom()
    }
}
