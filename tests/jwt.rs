use jwt::VerifyingAlgorithm;
use permissions::{CanDeleteApp, CanViewApps};

use gdp::{
    named::name,
    proof::Proof,
    prop::{or_l, or_r},
};

use crate::{
    jwt::{has_azure_role, has_okta_role, Admin, Azure, Jwt, Key, Okta},
    permissions::{can_delete_app, can_view_apps},
};

pub mod jwt {
    use std::ops::Deref;

    use gdp::{
        named::{Name, Named},
        proof::{axiom, Proof},
    };
    use jwt::{VerifyWithKey, VerifyingAlgorithm};
    use serde_json::Value;

    pub trait Role {
        fn name(&self) -> &'static str;
    }

    pub struct Admin;

    impl Role for Admin {
        fn name(&self) -> &'static str {
            "admin"
        }
    }

    pub struct Key<A, I>(A, I);
    impl<A, I> Key<A, I> {
        pub fn new(key: A, issuer: I) -> Self {
            Key(key, issuer)
        }
    }

    pub struct Azure;
    pub struct Okta;
    pub struct IssuedBy<'name, I>(Name<'name>, I);
    pub struct HasRole<'name, R>(Name<'name>, R);

    pub struct Jwt {
        token: jwt::Token<jwt::Header, Value, jwt::token::Verified>,
    }

    pub struct JwtOf<'name>(Name<'name>, Jwt);
    impl<'name> Deref for JwtOf<'name> {
        type Target = Jwt;

        fn deref(&self) -> &Self::Target {
            &self.1
        }
    }

    impl Jwt {
        /// Validate given token with given key
        pub fn new<'name, I>(
            key: &Key<impl VerifyingAlgorithm, I>,
            token_str: Named<'name, &str>,
        ) -> Result<(JwtOf<'name>, Proof<IssuedBy<'name, I>>), jwt::Error> {
            let token = token_str.verify_with_key(&key.0)?;
            Ok((JwtOf(token_str.name(), Jwt { token }), axiom()))
        }
    }

    /// Check that the token gotten from azure has given role
    pub fn has_azure_role<'name, R: Role>(
        jwt: &JwtOf<'name>,
        role: R,
        _: Proof<IssuedBy<'name, Azure>>,
    ) -> Option<Proof<HasRole<'name, R>>> {
        let roles = jwt.token.claims().get("roles")?;
        roles
            .as_array()?
            .iter()
            .filter_map(|r| r.as_str())
            .any(|r| r == role.name())
            .then(axiom)
    }

    /// Check that the token gotten from okta has given role
    pub fn has_okta_role<'name, R: Role>(
        jwt: &JwtOf<'name>,
        role: R,
        _: Proof<IssuedBy<'name, Okta>>,
    ) -> Option<Proof<HasRole<'name, R>>> {
        jwt.token.claims().get(role.name())?.as_bool()?.then(axiom)
    }
}

pub mod permissions {
    use gdp::{
        named::Name,
        proof::{axiom, Proof},
        prop::Or,
    };

    use crate::jwt::{Admin, Azure, HasRole, IssuedBy, Okta};

    pub struct CanViewApps<'name>(Name<'name>);
    /// One can view apps if they have JWT issued by azure or okta
    pub fn can_view_apps<'name>(
        _: Proof<Or<IssuedBy<'name, Azure>, IssuedBy<'name, Okta>>>,
    ) -> Proof<CanViewApps<'name>> {
        axiom()
    }

    pub struct CanDeleteApp<'name>(Name<'name>);
    /// One can delete apps if they have JWT with admin role
    pub fn can_delete_app<'name>(_: Proof<HasRole<'name, Admin>>) -> Proof<CanDeleteApp<'name>> {
        axiom()
    }
}

#[derive(PartialEq, Debug)]
pub enum Error {
    NoRole,
    JwtParseFailed,
}

pub fn delete_app(_: Proof<CanDeleteApp>) -> String {
    "Nuke it to the ground".to_owned()
}

pub fn list_apps(_: Proof<CanViewApps>) -> Vec<String> {
    vec!["app1".to_owned(), "app2".to_owned()]
}

pub fn try_to_list_apps(
    token_str: &str,
    azure_key: &Key<impl VerifyingAlgorithm, Azure>,
    okta_key: &Key<impl VerifyingAlgorithm, Okta>,
) -> Result<Vec<String>, Error> {
    name(&*token_str, |token_str| {
        let p = Jwt::new(&azure_key, token_str.clone())
            .map(|(_, p)| or_l(p))
            .or_else(|_| Jwt::new(&okta_key, token_str).map(|(_, p)| or_r(p)))
            .map_err(|_| Error::JwtParseFailed)?;
        let p = can_view_apps(p);
        Ok(list_apps(p))
    })
}

pub fn try_to_delete_app(
    token_str: &str,
    azure_key: &Key<impl VerifyingAlgorithm, Azure>,
    okta_key: &Key<impl VerifyingAlgorithm, Okta>,
) -> Result<String, Error> {
    name(&*token_str, |token_str| {
        let (_, p) = Jwt::new(&azure_key, token_str.clone())
            .map_err(|_| Error::JwtParseFailed)
            .and_then(|(jwt, p)| {
                has_azure_role(&jwt, Admin, p)
                    .map(|p| (jwt, p))
                    .ok_or_else(|| Error::NoRole)
            })
            .or_else(|_| {
                Jwt::new(&okta_key, token_str)
                    .map_err(|_| Error::JwtParseFailed)
                    .and_then(|(jwt, p)| {
                        has_okta_role(&jwt, Admin, p)
                            .map(|p| (jwt, p))
                            .ok_or_else(|| Error::NoRole)
                    })
            })
            .map_err(|_| Error::JwtParseFailed)?;
        let p = can_delete_app(p);
        Ok(delete_app(p))
    })
}

#[cfg(test)]
mod tests {
    use crate::{
        jwt::{Azure, Key, Okta},
        try_to_delete_app, try_to_list_apps, Error,
    };
    use serde_json::{json, Map, Value};

    use jwt::{FromBase64, ToBase64};

    struct DummyAlgo(String);

    impl jwt::VerifyingAlgorithm for DummyAlgo {
        fn algorithm_type(&self) -> jwt::AlgorithmType {
            jwt::AlgorithmType::None
        }

        fn verify_bytes(
            &self,
            header: &str,
            _claims: &str,
            _signature: &[u8],
        ) -> Result<bool, jwt::Error> {
            let header = Value::from_base64(header)?;
            Ok(header
                .get("from")
                .ok_or_else(|| jwt::Error::InvalidSignature)?
                .as_str()
                .ok_or_else(|| jwt::Error::InvalidSignature)?
                == self.0)
        }
    }

    fn construct_jwt(fake: &str, roles: Vec<&str>) -> String {
        let header = json!({
            "alg": "none",
            "from": fake
        });
        let claims = json!({ "roles": roles });
        format!(
            "{}.{}.",
            header.to_base64().unwrap(),
            claims.to_base64().unwrap()
        )
    }

    fn construct_azure_jwt(roles: Vec<&str>) -> String {
        let header = json!({
            "alg": "none",
            "from": "azure"
        });
        let claims = json!({ "roles": roles });
        format!(
            "{}.{}.",
            header.to_base64().unwrap(),
            claims.to_base64().unwrap()
        )
    }

    fn construct_okta_jwt(roles: Vec<&str>) -> String {
        let header = json!({
            "alg": "none",
            "from": "okta"
        });
        let val = Value::Object(Map::from_iter(
            roles.into_iter().map(|r| (r.to_owned(), Value::Bool(true))),
        ));
        let claims = json!(val);
        format!(
            "{}.{}.",
            header.to_base64().unwrap(),
            claims.to_base64().unwrap()
        )
    }

    #[test]
    fn test_app_listing_with_azure_token() {
        let token_str = construct_azure_jwt(vec![]);
        let azure_key = Key::new(DummyAlgo("azure".to_owned()), Azure);
        let okta_key = Key::new(DummyAlgo("okta".to_owned()), Okta);

        assert_eq!(
            Ok::<_, crate::Error>(vec!["app1".to_owned(), "app2".to_owned()]),
            try_to_list_apps(&token_str, &azure_key, &okta_key)
        );
    }

    #[test]
    fn test_app_listing_with_okta_token() {
        let token_str = construct_okta_jwt(vec![]);
        let azure_key = Key::new(DummyAlgo("azure".to_owned()), Azure);
        let okta_key = Key::new(DummyAlgo("okta".to_owned()), Okta);

        assert_eq!(
            Ok::<_, crate::Error>(vec!["app1".to_owned(), "app2".to_owned()]),
            try_to_list_apps(&token_str, &azure_key, &okta_key)
        );
    }

    #[test]
    fn test_app_deletion_with_valid_azure_token() {
        let token_str = construct_azure_jwt(vec!["admin"]);
        let azure_key = Key::new(DummyAlgo("azure".to_owned()), Azure);
        let okta_key = Key::new(DummyAlgo("okta".to_owned()), Okta);
        assert_eq!(
            Ok::<_, crate::Error>("Nuke it to the ground".to_owned()),
            try_to_delete_app(&token_str, &azure_key, &okta_key)
        );
    }

    #[test]
    fn test_app_deletion_with_valid_okta_token() {
        let token_str = construct_okta_jwt(vec!["admin"]);
        let azure_key = Key::new(DummyAlgo("azure".to_owned()), Azure);
        let okta_key = Key::new(DummyAlgo("okta".to_owned()), Okta);
        assert_eq!(
            Ok::<_, crate::Error>("Nuke it to the ground".to_owned()),
            try_to_delete_app(&token_str, &azure_key, &okta_key)
        );
    }

    #[test]
    fn test_app_deletion_with_invalid_token() {
        let token_str = construct_jwt("fake", vec!["admin"]);
        let azure_key = Key::new(DummyAlgo("azure".to_owned()), Azure);
        let okta_key = Key::new(DummyAlgo("okta".to_owned()), Okta);
        assert_eq!(
            Err(Error::JwtParseFailed),
            try_to_delete_app(&token_str, &azure_key, &okta_key)
        );
    }
}
