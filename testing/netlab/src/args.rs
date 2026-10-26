//! Tiny `--key value` argument parser for the lab binaries (std only).

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

/// Parsed arguments: repeatable `--key value` options and bare `--flag`s.
#[derive(Debug, Default)]
pub struct Args {
    values: HashMap<String, Vec<String>>,
    flags: Vec<String>,
}

/// An argument error, printed with the usage text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgError(pub String);

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ArgError {}

impl Args {
    /// Parses `argv` (without the program name). `value_keys` take a value;
    /// `flag_keys` do not. Anything else is an error.
    pub fn parse<I>(argv: I, value_keys: &[&str], flag_keys: &[&str]) -> Result<Self, ArgError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut out = Self::default();
        let mut it = argv.into_iter();
        while let Some(arg) = it.next() {
            let Some(key) = arg.strip_prefix("--") else {
                return Err(ArgError(format!("unexpected argument: {arg}")));
            };
            if flag_keys.contains(&key) {
                out.flags.push(key.to_owned());
            } else if value_keys.contains(&key) {
                let Some(value) = it.next() else {
                    return Err(ArgError(format!("--{key} needs a value")));
                };
                out.values.entry(key.to_owned()).or_default().push(value);
            } else {
                return Err(ArgError(format!("unknown option: --{key}")));
            }
        }
        Ok(out)
    }

    /// Whether `--key` was given as a flag.
    pub fn flag(&self, key: &str) -> bool {
        self.flags.iter().any(|f| f == key)
    }

    /// Every value of a repeatable option.
    pub fn all(&self, key: &str) -> &[String] {
        self.values.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The single value of an option, parsed; `None` if absent.
    pub fn opt<T: FromStr>(&self, key: &str) -> Result<Option<T>, ArgError> {
        match self.all(key) {
            [] => Ok(None),
            [v] => v
                .parse()
                .map(Some)
                .map_err(|_| ArgError(format!("bad value for --{key}: {v}"))),
            _ => Err(ArgError(format!("--{key} given more than once"))),
        }
    }

    /// The single value of a required option, parsed.
    pub fn req<T: FromStr>(&self, key: &str) -> Result<T, ArgError> {
        self.opt(key)?
            .ok_or_else(|| ArgError(format!("--{key} is required")))
    }

    /// Every value of a repeatable option, parsed.
    pub fn parse_all<T: FromStr>(&self, key: &str) -> Result<Vec<T>, ArgError> {
        self.all(key)
            .iter()
            .map(|v| {
                v.parse()
                    .map_err(|_| ArgError(format!("bad value for --{key}: {v}")))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_values_flags_and_repeats() {
        let a = Args::parse(
            argv("--server 10.0.0.1 --server 10.0.0.2 --port 67 --tsize"),
            &["server", "port"],
            &["tsize"],
        )
        .unwrap();
        assert_eq!(
            a.parse_all::<std::net::Ipv4Addr>("server").unwrap().len(),
            2
        );
        assert_eq!(a.req::<u16>("port").unwrap(), 67);
        assert!(a.flag("tsize"));
        assert_eq!(a.opt::<u16>("missing").unwrap(), None);
        assert!(a.req::<u16>("missing").is_err());
        assert!(a.opt::<std::net::Ipv4Addr>("server").is_err());
    }

    #[test]
    fn rejects_unknown_and_missing_values() {
        assert!(Args::parse(argv("--nope 1"), &["port"], &[]).is_err());
        assert!(Args::parse(argv("--port"), &["port"], &[]).is_err());
        assert!(Args::parse(argv("stray"), &["port"], &[]).is_err());
        let a = Args::parse(argv("--port x"), &["port"], &[]).unwrap();
        assert!(a.req::<u16>("port").is_err());
    }
}
