//! The pinned A2A `AgentCard` shape and its field-presence table.
//!
//! Derived by hand from `specification/a2a.proto` at A2A v1.0.1, commit
//! `3303592588e388e62e0f69f701af531d2f4e3991`. This table is the one piece of
//! the system that no off-the-shelf library provides, because A2A §8.4.1
//! requires protobuf field-presence semantics to be applied to the JSON before
//! canonicalization. Re-derive it whenever the pinned commit moves.
//!
//! JSON member names are the proto3 lowerCamelCase mapping of the proto field
//! names, matching the sample card in A2A §8.5.

/// How a field behaves with respect to presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    /// `[(google.api.field_behavior) = REQUIRED]`. Always present, even when
    /// its value equals the default.
    Required,
    /// The proto3 `optional` keyword: explicit presence. May be present
    /// carrying the default value; absence is also legal.
    Optional,
    /// Implicit presence. Must be omitted when the value is the default.
    /// Singular message fields and `oneof` members are also placed here, but
    /// they carry explicit presence in proto3, so an empty object is legal for
    /// them — see [`Ty::default_is_omittable`].
    Implicit,
}

/// The type of a field, to the depth the presence rules care about.
#[derive(Debug, Clone, Copy)]
pub enum Ty {
    Str,
    Bool,
    /// A nested message with its own field table.
    Msg(&'static Msg),
    /// `google.protobuf.Struct`: free-form JSON. Contents are not validated,
    /// only canonicalized.
    Struct,
    Repeated(&'static Ty),
    Map(&'static Ty),
}

impl Ty {
    /// Whether an implicit-presence field of this type has a "default value"
    /// that must be omitted.
    ///
    /// Scalars, repeated fields and maps do. Message fields do not: in proto3
    /// a singular message always tracks presence, so an explicitly present
    /// empty object is distinct from absence and is legal.
    pub fn default_is_omittable(&self) -> bool {
        match self {
            Ty::Str | Ty::Bool | Ty::Repeated(_) | Ty::Map(_) => true,
            Ty::Msg(_) | Ty::Struct => false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub behavior: Behavior,
    pub ty: Ty,
}

#[derive(Debug)]
pub struct Msg {
    pub name: &'static str,
    pub fields: &'static [Field],
    /// A `oneof` wrapper: at most one member may be present.
    pub is_oneof: bool,
}

const fn req(name: &'static str, ty: Ty) -> Field {
    Field {
        name,
        behavior: Behavior::Required,
        ty,
    }
}
const fn opt(name: &'static str, ty: Ty) -> Field {
    Field {
        name,
        behavior: Behavior::Optional,
        ty,
    }
}
const fn imp(name: &'static str, ty: Ty) -> Field {
    Field {
        name,
        behavior: Behavior::Implicit,
        ty,
    }
}

/// The root of the pinned schema.
pub static AGENT_CARD: Msg = Msg {
    name: "AgentCard",
    is_oneof: false,
    fields: &[
        req("name", Ty::Str),
        req("description", Ty::Str),
        req(
            "supportedInterfaces",
            Ty::Repeated(&Ty::Msg(&AGENT_INTERFACE)),
        ),
        imp("provider", Ty::Msg(&AGENT_PROVIDER)),
        req("version", Ty::Str),
        opt("documentationUrl", Ty::Str),
        req("capabilities", Ty::Msg(&AGENT_CAPABILITIES)),
        imp("securitySchemes", Ty::Map(&Ty::Msg(&SECURITY_SCHEME))),
        imp(
            "securityRequirements",
            Ty::Repeated(&Ty::Msg(&SECURITY_REQUIREMENT)),
        ),
        req("defaultInputModes", Ty::Repeated(&Ty::Str)),
        req("defaultOutputModes", Ty::Repeated(&Ty::Str)),
        req("skills", Ty::Repeated(&Ty::Msg(&AGENT_SKILL))),
        imp("signatures", Ty::Repeated(&Ty::Msg(&AGENT_CARD_SIGNATURE))),
        opt("iconUrl", Ty::Str),
    ],
};

static AGENT_INTERFACE: Msg = Msg {
    name: "AgentInterface",
    is_oneof: false,
    fields: &[
        req("url", Ty::Str),
        req("protocolBinding", Ty::Str),
        imp("tenant", Ty::Str),
        req("protocolVersion", Ty::Str),
    ],
};

static AGENT_PROVIDER: Msg = Msg {
    name: "AgentProvider",
    is_oneof: false,
    fields: &[req("url", Ty::Str), req("organization", Ty::Str)],
};

static AGENT_CAPABILITIES: Msg = Msg {
    name: "AgentCapabilities",
    is_oneof: false,
    fields: &[
        opt("streaming", Ty::Bool),
        opt("pushNotifications", Ty::Bool),
        imp("extensions", Ty::Repeated(&Ty::Msg(&AGENT_EXTENSION))),
        opt("extendedAgentCard", Ty::Bool),
    ],
};

static AGENT_EXTENSION: Msg = Msg {
    name: "AgentExtension",
    is_oneof: false,
    fields: &[
        imp("uri", Ty::Str),
        imp("description", Ty::Str),
        imp("required", Ty::Bool),
        imp("params", Ty::Struct),
    ],
};

static AGENT_SKILL: Msg = Msg {
    name: "AgentSkill",
    is_oneof: false,
    fields: &[
        req("id", Ty::Str),
        req("name", Ty::Str),
        req("description", Ty::Str),
        req("tags", Ty::Repeated(&Ty::Str)),
        imp("examples", Ty::Repeated(&Ty::Str)),
        imp("inputModes", Ty::Repeated(&Ty::Str)),
        imp("outputModes", Ty::Repeated(&Ty::Str)),
        imp(
            "securityRequirements",
            Ty::Repeated(&Ty::Msg(&SECURITY_REQUIREMENT)),
        ),
    ],
};

static AGENT_CARD_SIGNATURE: Msg = Msg {
    name: "AgentCardSignature",
    is_oneof: false,
    fields: &[
        req("protected", Ty::Str),
        req("signature", Ty::Str),
        imp("header", Ty::Struct),
    ],
};

static SECURITY_REQUIREMENT: Msg = Msg {
    name: "SecurityRequirement",
    is_oneof: false,
    fields: &[imp("schemes", Ty::Map(&Ty::Msg(&STRING_LIST)))],
};

static STRING_LIST: Msg = Msg {
    name: "StringList",
    is_oneof: false,
    fields: &[imp("list", Ty::Repeated(&Ty::Str))],
};

// `oneof scheme`. Proto permits zero members set, so the validator allows an
// empty object here rather than inventing a constraint the pinned schema does
// not express.
static SECURITY_SCHEME: Msg = Msg {
    name: "SecurityScheme",
    is_oneof: true,
    fields: &[
        imp("apiKeySecurityScheme", Ty::Msg(&API_KEY_SCHEME)),
        imp("httpAuthSecurityScheme", Ty::Msg(&HTTP_AUTH_SCHEME)),
        imp("oauth2SecurityScheme", Ty::Msg(&OAUTH2_SCHEME)),
        imp("openIdConnectSecurityScheme", Ty::Msg(&OIDC_SCHEME)),
        imp("mtlsSecurityScheme", Ty::Msg(&MTLS_SCHEME)),
    ],
};

static API_KEY_SCHEME: Msg = Msg {
    name: "APIKeySecurityScheme",
    is_oneof: false,
    fields: &[
        imp("description", Ty::Str),
        req("location", Ty::Str),
        req("name", Ty::Str),
    ],
};

static HTTP_AUTH_SCHEME: Msg = Msg {
    name: "HTTPAuthSecurityScheme",
    is_oneof: false,
    fields: &[
        imp("description", Ty::Str),
        req("scheme", Ty::Str),
        imp("bearerFormat", Ty::Str),
    ],
};

static OAUTH2_SCHEME: Msg = Msg {
    name: "OAuth2SecurityScheme",
    is_oneof: false,
    fields: &[
        imp("description", Ty::Str),
        req("flows", Ty::Msg(&OAUTH_FLOWS)),
        imp("oauth2MetadataUrl", Ty::Str),
    ],
};

static OIDC_SCHEME: Msg = Msg {
    name: "OpenIdConnectSecurityScheme",
    is_oneof: false,
    fields: &[
        imp("description", Ty::Str),
        req("openIdConnectUrl", Ty::Str),
    ],
};

static MTLS_SCHEME: Msg = Msg {
    name: "MutualTlsSecurityScheme",
    is_oneof: false,
    fields: &[imp("description", Ty::Str)],
};

static OAUTH_FLOWS: Msg = Msg {
    name: "OAuthFlows",
    is_oneof: true,
    fields: &[
        imp("authorizationCode", Ty::Msg(&AUTHORIZATION_CODE_FLOW)),
        imp("clientCredentials", Ty::Msg(&CLIENT_CREDENTIALS_FLOW)),
        imp("implicit", Ty::Msg(&IMPLICIT_FLOW)),
        imp("password", Ty::Msg(&PASSWORD_FLOW)),
        imp("deviceCode", Ty::Msg(&DEVICE_CODE_FLOW)),
    ],
};

static AUTHORIZATION_CODE_FLOW: Msg = Msg {
    name: "AuthorizationCodeOAuthFlow",
    is_oneof: false,
    fields: &[
        req("authorizationUrl", Ty::Str),
        req("tokenUrl", Ty::Str),
        imp("refreshUrl", Ty::Str),
        req("scopes", Ty::Map(&Ty::Str)),
        imp("pkceRequired", Ty::Bool),
    ],
};

static CLIENT_CREDENTIALS_FLOW: Msg = Msg {
    name: "ClientCredentialsOAuthFlow",
    is_oneof: false,
    fields: &[
        req("tokenUrl", Ty::Str),
        imp("refreshUrl", Ty::Str),
        req("scopes", Ty::Map(&Ty::Str)),
    ],
};

static IMPLICIT_FLOW: Msg = Msg {
    name: "ImplicitOAuthFlow",
    is_oneof: false,
    fields: &[
        imp("authorizationUrl", Ty::Str),
        imp("refreshUrl", Ty::Str),
        imp("scopes", Ty::Map(&Ty::Str)),
    ],
};

static PASSWORD_FLOW: Msg = Msg {
    name: "PasswordOAuthFlow",
    is_oneof: false,
    fields: &[
        imp("tokenUrl", Ty::Str),
        imp("refreshUrl", Ty::Str),
        imp("scopes", Ty::Map(&Ty::Str)),
    ],
};

static DEVICE_CODE_FLOW: Msg = Msg {
    name: "DeviceCodeOAuthFlow",
    is_oneof: false,
    fields: &[
        req("deviceAuthorizationUrl", Ty::Str),
        req("tokenUrl", Ty::Str),
        imp("refreshUrl", Ty::Str),
        req("scopes", Ty::Map(&Ty::Str)),
    ],
};

// --- identifying the table -----------------------------------------------

/// A digest over the presence table itself.
///
/// A2A pins a protocol commit; it does not publish the presence table derived
/// from it, because the table only exists once someone applies §8.4.1's rules
/// to the proto by hand — which is what this module is. Two implementations
/// that read the same commit can still disagree about a single field's
/// behaviour, and that disagreement produces two different canonical documents
/// and so two different signatures over what looks like the same card.
///
/// Publishing this digest is what turns "we pinned the same commit" into
/// something checkable. It is computed from the table's own contents, so it
/// cannot drift from the table it names.
pub fn table_digest() -> &'static str {
    use std::sync::OnceLock;
    static DIGEST: OnceLock<String> = OnceLock::new();
    DIGEST.get_or_init(|| {
        let mut out = String::new();
        render_msg(&AGENT_CARD, &mut out, &mut Vec::new());
        format!("sha256:{:x}", <sha2::Sha256 as sha2::Digest>::digest(out))
    })
}

/// Render one message deterministically. `seen` breaks the recursion on the
/// mutually referential parts of the schema; a message already rendered
/// contributes its name alone.
fn render_msg(msg: &'static Msg, out: &mut String, seen: &mut Vec<&'static str>) {
    if seen.contains(&msg.name) {
        out.push_str(msg.name);
        out.push_str(";\n");
        return;
    }
    seen.push(msg.name);

    out.push_str(msg.name);
    if msg.is_oneof {
        out.push_str("|oneof");
    }
    out.push_str("{\n");
    for field in msg.fields {
        out.push_str("  ");
        out.push_str(field.name);
        out.push(':');
        out.push_str(match field.behavior {
            Behavior::Required => "required",
            Behavior::Optional => "optional",
            Behavior::Implicit => "implicit",
        });
        out.push(' ');
        render_ty(&field.ty, out, seen);
        out.push('\n');
    }
    out.push_str("}\n");
}

fn render_ty(ty: &'static Ty, out: &mut String, seen: &mut Vec<&'static str>) {
    match ty {
        Ty::Str => out.push_str("string"),
        Ty::Bool => out.push_str("bool"),
        Ty::Struct => out.push_str("struct"),
        Ty::Msg(m) => render_msg(m, out, seen),
        Ty::Repeated(inner) => {
            out.push_str("repeated<");
            render_ty(inner, out, seen);
            out.push('>');
        }
        Ty::Map(inner) => {
            out.push_str("map<");
            render_ty(inner, out, seen);
            out.push('>');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The digest is a published interoperability fact. If this test fails, the
    /// table changed — which is legitimate when the pinned A2A commit moves, and
    /// a bug otherwise. Either way it must be a deliberate edit, not a surprise.
    /// The digest is a published interoperability fact, so it is pinned here as
    /// a literal. Asserting only that it equals itself made the doc comment
    /// above false: an accidental edit to the presence table would change every
    /// card's canonical form and the digest the manifest serves, with a green
    /// suite. If this fails, either the pinned A2A commit moved — in which case
    /// update the literal deliberately, in the same commit as the table — or
    /// the table was changed by accident.
    #[test]
    fn the_table_digest_is_pinned() {
        assert_eq!(table_digest(), EXPECTED);
    }

    const EXPECTED: &str =
        "sha256:cc3191a655d53847bed8f0afcb8138932daea9184a20ee2420e49287b39c9b84";
}
