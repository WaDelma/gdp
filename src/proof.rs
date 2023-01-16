use std::marker::PhantomData as PD;

/// Holds proof of P without using any memory 👻.
#[derive(Clone, Copy)]
pub struct Proof<P>(PD<P>);

/// Used by library author to assert axioms. Essentially conjures proof out of thin air.
/// 
/// *NOTE*: Incorrect usage can cause contradictions, so be careful.
pub fn axiom<P>() -> Proof<P> {
    Proof(PD)
}

/// Can be used to conjure proof for anything out of thin air.
///
/// *NOTE*: Should be only used for stubbing when working on proofs and not
/// present in complete proofs. Usage *will* subvert whole proof system.
pub fn sorry<P>() -> Proof<P> {
    Proof(PD)
}
