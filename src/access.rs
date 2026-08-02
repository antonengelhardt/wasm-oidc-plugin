//! Optional access rules evaluated against OpenID ID token claims.
//!
//! Rules are configured as strings. Any matching rule grants access (OR).
//! Conditions within a single rule are AND'd with `&`.
//!
//! Supported condition operators:
//! * `claim==value` — exact match (arrays match if any element equals `value`)
//! * `claim=~regex` — regex match against a string claim, or any array element

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as base64engine_urlsafe, Engine as _};
use regex::Regex;
use serde_json::{Map, Value};

use crate::error::PluginError;

/// A single condition comparing one claim to an expected value or pattern.
#[derive(Debug, Clone)]
pub enum Condition {
    /// Exact equality (`claim==value`).
    Equals { claim: String, value: String },
    /// Regex match (`claim=~pattern`).
    Matches { claim: String, regex: Regex },
}

/// One access rule: all conditions must match (AND).
#[derive(Debug, Clone)]
pub struct AccessRule {
    pub conditions: Vec<Condition>,
}

impl AccessRule {
    /// Parse a rule string such as `email==a@b.com & groups==admins`.
    pub fn parse(rule: &str) -> Result<Self, PluginError> {
        let trimmed = rule.trim();
        if trimmed.is_empty() {
            return Err(PluginError::AccessRuleParseError(
                "access rule must not be empty".to_string(),
            ));
        }

        let mut conditions = Vec::new();
        for part in trimmed.split('&') {
            let part = part.trim();
            if part.is_empty() {
                return Err(PluginError::AccessRuleParseError(format!(
                    "empty condition in access rule: {rule}"
                )));
            }
            conditions.push(Condition::parse(part)?);
        }

        Ok(AccessRule { conditions })
    }

    /// Returns true if every condition matches the given claims.
    pub fn matches(&self, claims: &Map<String, Value>) -> bool {
        self.conditions.iter().all(|c| c.matches(claims))
    }
}

impl Condition {
    /// Parse a single condition (`claim==value` or `claim=~regex`).
    pub fn parse(condition: &str) -> Result<Self, PluginError> {
        match find_operator(condition) {
            Some((claim, "==", value)) => {
                if claim.is_empty() || value.is_empty() {
                    return Err(PluginError::AccessRuleParseError(format!(
                        "invalid equals condition: {condition}"
                    )));
                }
                Ok(Condition::Equals {
                    claim: claim.to_string(),
                    value: value.to_string(),
                })
            }
            Some((claim, "=~", pattern)) => {
                if claim.is_empty() || pattern.is_empty() {
                    return Err(PluginError::AccessRuleParseError(format!(
                        "invalid matches condition: {condition}"
                    )));
                }
                let regex = Regex::new(pattern).map_err(|e| {
                    PluginError::AccessRuleParseError(format!(
                        "invalid regex in access rule `{condition}`: {e}"
                    ))
                })?;
                Ok(Condition::Matches {
                    claim: claim.to_string(),
                    regex,
                })
            }
            _ => Err(PluginError::AccessRuleParseError(format!(
                "access condition must use `==` or `=~`: {condition}"
            ))),
        }
    }

    /// Returns true if this condition matches the given claims.
    pub fn matches(&self, claims: &Map<String, Value>) -> bool {
        match self {
            Condition::Equals { claim, value } => match claims.get(claim) {
                Some(Value::String(s)) => s == value,
                Some(Value::Number(n)) => n.to_string() == *value,
                Some(Value::Bool(b)) => b.to_string() == *value,
                Some(Value::Array(arr)) => arr.iter().any(|item| match item {
                    Value::String(s) => s == value,
                    Value::Number(n) => n.to_string() == *value,
                    Value::Bool(b) => b.to_string() == *value,
                    _ => false,
                }),
                _ => false,
            },
            Condition::Matches { claim, regex } => match claims.get(claim) {
                Some(Value::String(s)) => regex.is_match(s),
                Some(Value::Number(n)) => regex.is_match(&n.to_string()),
                Some(Value::Bool(b)) => regex.is_match(&b.to_string()),
                Some(Value::Array(arr)) => arr.iter().any(|item| match item {
                    Value::String(s) => regex.is_match(s),
                    Value::Number(n) => regex.is_match(&n.to_string()),
                    Value::Bool(b) => regex.is_match(&b.to_string()),
                    _ => false,
                }),
                _ => false,
            },
        }
    }
}

/// Find the first `==` or `=~` operator in `input` and split around it.
fn find_operator(input: &str) -> Option<(&str, &str, &str)> {
    let eq = input.find("==");
    let re = input.find("=~");
    match (eq, re) {
        (Some(i), Some(j)) if i <= j => Some((input[..i].trim(), "==", input[i + 2..].trim())),
        (Some(i), None) => Some((input[..i].trim(), "==", input[i + 2..].trim())),
        (None, Some(j)) | (Some(_), Some(j)) => {
            Some((input[..j].trim(), "=~", input[j + 2..].trim()))
        }
        (None, None) => None,
    }
}

/// Parse a list of rule strings into compiled [`AccessRule`]s.
pub fn parse_rules(rules: &[String]) -> Result<Vec<AccessRule>, PluginError> {
    rules.iter().map(|r| AccessRule::parse(r)).collect()
}

/// Returns true if `rules` is empty or any rule matches `claims`.
pub fn evaluate(rules: &[AccessRule], claims: &Map<String, Value>) -> bool {
    if rules.is_empty() {
        return true;
    }
    rules.iter().any(|rule| rule.matches(claims))
}

/// Decode the JWT payload (middle segment) into a JSON object of claims.
///
/// Does not verify the signature — callers must already trust the token
/// (e.g. after JWT validation or because it came from the encrypted session).
pub fn decode_jwt_claims(token: &str) -> Result<Map<String, Value>, PluginError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or_else(|| {
        PluginError::AccessRuleParseError("id token is not a valid JWT".to_string())
    })?;
    let payload = parts.next().ok_or_else(|| {
        PluginError::AccessRuleParseError("id token is not a valid JWT".to_string())
    })?;

    let decoded = base64engine_urlsafe.decode(payload.as_bytes())?;

    let value: Value = serde_json::from_slice(&decoded)?;
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(PluginError::AccessRuleParseError(
            "id token payload is not a JSON object".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn claims(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn parse_equals_condition() {
        let rule = AccessRule::parse("email==admin@company.com").unwrap();
        assert_eq!(rule.conditions.len(), 1);
        match &rule.conditions[0] {
            Condition::Equals { claim, value } => {
                assert_eq!(claim, "email");
                assert_eq!(value, "admin@company.com");
            }
            _ => panic!("expected Equals"),
        }
    }

    #[test]
    fn parse_matches_condition() {
        let rule = AccessRule::parse(r"email=~.*@company\.com$").unwrap();
        match &rule.conditions[0] {
            Condition::Matches { claim, regex } => {
                assert_eq!(claim, "email");
                assert!(regex.is_match("user@company.com"));
            }
            _ => panic!("expected Matches"),
        }
    }

    #[test]
    fn parse_and_conditions() {
        let rule = AccessRule::parse("email==a@b.com & groups==admins").unwrap();
        assert_eq!(rule.conditions.len(), 2);
    }

    #[test]
    fn parse_trims_whitespace() {
        let rule = AccessRule::parse("  email == a@b.com  &  groups == admins  ").unwrap();
        assert_eq!(rule.conditions.len(), 2);
        match &rule.conditions[0] {
            Condition::Equals { claim, value } => {
                assert_eq!(claim, "email");
                assert_eq!(value, "a@b.com");
            }
            _ => panic!("expected Equals"),
        }
    }

    #[test]
    fn parse_rejects_empty_rule() {
        assert!(AccessRule::parse("").is_err());
        assert!(AccessRule::parse("   ").is_err());
    }

    #[test]
    fn parse_rejects_missing_operator() {
        assert!(AccessRule::parse("email").is_err());
    }

    #[test]
    fn parse_rejects_invalid_regex() {
        assert!(AccessRule::parse("email=~[").is_err());
    }

    #[test]
    fn evaluate_or_across_rules() {
        let rules = parse_rules(&[
            "email==admin@company.com".to_string(),
            "groups==admins".to_string(),
        ])
        .unwrap();
        let c = claims(json!({"email": "other@company.com", "groups": ["admins"]}));
        assert!(evaluate(&rules, &c));
    }

    #[test]
    fn evaluate_and_within_rule() {
        let rules = parse_rules(&["email==user@company.com & groups==admins".to_string()]).unwrap();
        let ok = claims(json!({"email": "user@company.com", "groups": ["admins", "users"]}));
        let bad = claims(json!({"email": "user@company.com", "groups": ["users"]}));
        assert!(evaluate(&rules, &ok));
        assert!(!evaluate(&rules, &bad));
    }

    #[test]
    fn evaluate_string_equals() {
        let rules = parse_rules(&["email==admin@company.com".to_string()]).unwrap();
        let ok = claims(json!({"email": "admin@company.com"}));
        let bad = claims(json!({"email": "other@company.com"}));
        assert!(evaluate(&rules, &ok));
        assert!(!evaluate(&rules, &bad));
    }

    #[test]
    fn evaluate_array_contains() {
        let rules = parse_rules(&["groups==admins".to_string()]).unwrap();
        let ok = claims(json!({"groups": ["users", "admins"]}));
        let bad = claims(json!({"groups": ["users"]}));
        assert!(evaluate(&rules, &ok));
        assert!(!evaluate(&rules, &bad));
    }

    #[test]
    fn evaluate_regex_on_string_and_array() {
        let rules = parse_rules(&[r"email=~.*@company\.com$".to_string()]).unwrap();
        assert!(evaluate(
            &rules,
            &claims(json!({"email": "user@company.com"}))
        ));
        assert!(!evaluate(
            &rules,
            &claims(json!({"email": "user@other.com"}))
        ));

        let group_rules = parse_rules(&[r"groups=~^admin".to_string()]).unwrap();
        assert!(evaluate(
            &group_rules,
            &claims(json!({"groups": ["admins", "users"]}))
        ));
        assert!(!evaluate(
            &group_rules,
            &claims(json!({"groups": ["users"]}))
        ));
    }

    #[test]
    fn evaluate_missing_claim_denies() {
        let rules = parse_rules(&["email==admin@company.com".to_string()]).unwrap();
        let c = claims(json!({"sub": "123"}));
        assert!(!evaluate(&rules, &c));
    }

    #[test]
    fn evaluate_empty_rules_allows() {
        let c = claims(json!({}));
        assert!(evaluate(&[], &c));
    }

    #[test]
    fn decode_jwt_claims_extracts_payload() {
        // {"email":"a@b.com","groups":["admins"]}
        let payload = base64engine_urlsafe.encode(br#"{"email":"a@b.com","groups":["admins"]}"#);
        let token = format!("e30.{payload}.sig");
        let map = decode_jwt_claims(&token).unwrap();
        assert_eq!(map.get("email").unwrap().as_str().unwrap(), "a@b.com");
        assert!(map.get("groups").unwrap().as_array().unwrap().len() == 1);
    }

    #[test]
    fn decode_jwt_claims_rejects_invalid_token() {
        assert!(decode_jwt_claims("not-a-jwt").is_err());
        assert!(decode_jwt_claims("").is_err());
        assert!(decode_jwt_claims("aaa.!!!notbase64!!!").is_err());
    }

    #[test]
    fn parse_prefers_first_operator() {
        let rule = AccessRule::parse(r"email=~a==b").unwrap();
        match &rule.conditions[0] {
            Condition::Matches { claim, regex } => {
                assert_eq!(claim, "email");
                assert!(regex.is_match("a==b"));
            }
            _ => panic!("expected Matches when =~ appears first"),
        }
    }
}
