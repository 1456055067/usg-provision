//! Shared declarative macros.

/// A closed set of wire values: `Debug`/`Copy`/`Ord` enum with `ALL`,
/// `as_str`, `parse` (exact, case-sensitive), `Display`, and string serde
/// that refuses unknown text without echoing it.
macro_rules! closed_enum {
    (
        $(#[$doc:meta])*
        $name:ident, $field:literal {
            $( $(#[$vdoc:meta])* $variant:ident => $text:literal ),+ $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $( $(#[$vdoc])* $variant, )+
        }

        impl $name {
            /// Every value, in declaration order (for database check
            /// constraints and exhaustive tests).
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The wire text.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $text, )+
                }
            }

            /// Parses the exact wire text (case-sensitive). Anything else
            /// is `None`.
            #[must_use]
            pub fn parse(text: &str) -> Option<Self> {
                match text {
                    $( $text => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;

                impl serde::de::Visitor<'_> for V {
                    type Value = $name;

                    fn expecting(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                        f.write_str(concat!("a known ", $field, " value"))
                    }

                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$name, E> {
                        $name::parse(v).ok_or_else(|| {
                            E::custom(concat!("unknown ", $field, " value"))
                        })
                    }
                }

                d.deserialize_str(V)
            }
        }
    };
}
