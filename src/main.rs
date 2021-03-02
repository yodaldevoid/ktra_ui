use std::error::Error as StdError;
use std::fmt::{Display, Error as FmtError, Formatter};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use curl::easy::{Easy, List};
use curl::Error as CurlError;
use log::*;
use serde::Deserialize;
use serde_json::Error as JsonError;
use url::Url;

const DEFAULT_SERVER: &'static str = "localhost:8000";

#[derive(Debug)]
enum Error {
    NoServerResponse,
    Curl(CurlError),
    Json(JsonError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        match self {
            Self::NoServerResponse => write!(f, "No response from the server"),
            Self::Curl(e) => write!(f, "Curl error: {}", e),
            Self::Json(e) => write!(f, "JSON error: {}", e),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Curl(ref e) => Some(e),
            Self::Json(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<CurlError> for Error {
    fn from(e: CurlError) -> Self {
        Self::Curl(e)
    }
}

impl From<JsonError> for Error {
    fn from(e: JsonError) -> Self {
        Self::Json(e)
    }
}

fn main() -> Result<(), Error> {
    env_logger::init();

    let matches = App::new("Ktra UI")
        .version(
            format!(
                "{} ({} {})",
                option_env!("CARGO_PKG_VERSION").unwrap_or("unknown"),
                option_env!("VERGEN_SHA_SHORT").unwrap_or("unknown"),
                option_env!("VERGEN_COMMIT_DATE").unwrap_or("unknown")
            )
            .as_str(),
        )
        .author("Gabriel Smith <ga29smith@gmail.com>")
        .about("Provides a (slightly) better interface to Ktra than through curl.")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .arg(
            Arg::with_name("server")
                .short("s")
                .long("server")
                .takes_value(true)
                .empty_values(false)
                .validator(server_validator),
        )
        // TODO: flag to select https
        .subcommand(
            SubCommand::with_name("new")
                .arg(
                    Arg::with_name("user")
                        .takes_value(true)
                        .empty_values(false)
                        .required(true)
                        .validator(username_validator),
                )
                .arg(Arg::with_name("pass").empty_values(true).required(true)),
        )
        .subcommand(
            SubCommand::with_name("login")
                .arg(
                    Arg::with_name("user")
                        .takes_value(true)
                        .empty_values(false)
                        .required(true)
                        .validator(username_validator),
                )
                .arg(Arg::with_name("pass").empty_values(true).required(true)),
        )
        .subcommand(
            SubCommand::with_name("password")
                .arg(
                    Arg::with_name("user")
                        .takes_value(true)
                        .empty_values(false)
                        .required(true)
                        .validator(username_validator),
                )
                .arg(Arg::with_name("old_pass").empty_values(true).required(true))
                .arg(Arg::with_name("new_pass").empty_values(true).required(true)),
        )
        .get_matches();

    let server = matches.value_of("server").unwrap_or(DEFAULT_SERVER);

    match matches.subcommand() {
        ("new", Some(sub_m)) => new_user(sub_m, server),
        ("login", Some(sub_m)) => login_user(sub_m, server),
        ("password", Some(sub_m)) => change_password(sub_m, server),
        (_, _) => panic!("subcommand not matched"),
    }
}

fn server_validator(server: String) -> Result<(), String> {
    if let Err(e) = Url::parse(&server) {
        Err(format!("URL parsing error: {}", e))
    } else {
        Ok(())
    }
}

fn username_validator(username: String) -> Result<(), String> {
    if username.is_empty() {
        Err("usernames may not be empty".to_owned())
    } else if !username.chars().all(|c| match c {
        '0'..='9' | 'A'..='Z' | 'a'..='z' | '-' | '.' | '_' | '~' => true,
        _ => false,
    }) {
        Err("usernames may only contain 0-9, A-Z, a-z, '-', '.', '_', and '~'".to_owned())
    } else {
        Ok(())
    }
}

fn new_user(matches: &ArgMatches, server: &str) -> Result<(), Error> {
    let user = matches.value_of("user").expect("no username set");
    let pass = matches.value_of("pass").expect("no password set");

    info!("new_user: user=\"{}\" pass=\"{}\"", user, pass);

    let mut handle = Easy::new();
    handle.url(&format!("http://{}/ktra/api/v1/new_user/{}", server, user))?;
    handle.post(true)?;
    let mut headers = List::new();
    headers.append("Content-Type: application/json")?;
    handle.http_headers(headers)?;
    handle.post_fields_copy(
        format!("{{\"password\":{}}}", serde_json::to_string(pass)?).as_bytes(),
    )?;

    let mut response = None;
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            response = Some(serde_json::from_slice::<KtraResponse>(new_data));
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }
    response.ok_or(Error::NoServerResponse)??.print();

    Ok(())
}

fn login_user(matches: &ArgMatches, server: &str) -> Result<(), Error> {
    let user = matches.value_of("user").expect("no username set");
    let pass = matches.value_of("pass").expect("no password set");

    info!("login_user: user=\"{}\" pass=\"{}\"", user, pass);

    let mut handle = Easy::new();
    handle.url(&format!("http://{}/ktra/api/v1/login/{}", server, user))?;
    handle.post(true)?;
    let mut headers = List::new();
    headers.append("Content-Type: application/json")?;
    handle.http_headers(headers)?;
    handle.post_fields_copy(
        format!("{{\"password\":{}}}", serde_json::to_string(pass)?).as_bytes(),
    )?;

    let mut response = None;
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            response = Some(serde_json::from_slice::<KtraResponse>(new_data));
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }
    response.ok_or(Error::NoServerResponse)??.print();

    Ok(())
}

fn change_password(matches: &ArgMatches, server: &str) -> Result<(), Error> {
    let user = matches.value_of("user").expect("no username set");
    let old_pass = matches.value_of("old_pass").expect("no password set");
    let new_pass = matches.value_of("new_pass").expect("no password set");

    info!(
        "change_password: user=\"{}\" old_pass=\"{}\" new_pass=\"{}\"",
        user, old_pass, new_pass
    );

    let mut handle = Easy::new();
    handle.url(&format!(
        "http://{}/ktra/api/v1/change_password/{}",
        server, user,
    ))?;
    handle.post(true)?;
    let mut headers = List::new();
    headers.append("Content-Type: application/json")?;
    handle.http_headers(headers)?;
    handle.post_fields_copy(
        format!(
            "{{\"old_password\":{},\"new_password\":{}}}",
            serde_json::to_string(old_pass)?,
            serde_json::to_string(new_pass)?
        )
        .as_bytes(),
    )?;

    let mut response = None;
    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            response = Some(serde_json::from_slice::<KtraResponse>(new_data));
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }
    response.ok_or(Error::NoServerResponse)??.print();

    Ok(())
}

#[derive(Deserialize)]
struct KtraResponse {
    token: Option<String>,
    errors: Option<Vec<KtraError>>,
}

impl KtraResponse {
    fn print(&self) {
        if let Some(errors) = self.errors.as_ref() {
            eprintln!("Received errors:");
            for error in errors.iter() {
                eprintln!("- {}", error.detail);
            }
        } else if let Some(token) = self.token.as_ref() {
            print!("Token: {}", token);
        } else {
            panic!("Neither token nor errors exist");
        }
    }
}

#[derive(Deserialize)]
struct KtraError {
    detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_validate() {
        username_validator("Tester1-2.3_4~".to_owned())
            .expect("validator did not accept valid string");
    }

    #[test]
    fn username_validate_empty() {
        let message =
            username_validator("".to_owned()).expect_err("validator accepted an empty string");
        assert_eq!("usernames may not be empty", message);
    }

    #[test]
    fn username_validate_invalid_characters() {
        let valid_message = "usernames may only contain 0-9, A-Z, a-z, '-', '.', '_', and '~'";

        let message = username_validator("\u{0}".to_owned())
            .expect_err("validator accepted an invalid string");
        assert_eq!(valid_message, message);
        let message =
            username_validator("\\".to_owned()).expect_err("validator accepted an invalid string");
        assert_eq!(valid_message, message);
        let message =
            username_validator(" ".to_owned()).expect_err("validator accepted an invalid string");
        assert_eq!(valid_message, message);
        let message =
            username_validator(">".to_owned()).expect_err("validator accepted an invalid string");
        assert_eq!(valid_message, message);
    }

    #[test]
    fn json_deserialize_token() -> Result<(), Error> {
        let rsp: KtraResponse =
            serde_json::from_str(r#"{"token":"tokentokentokentokentokentokento"}"#)?;

        let token = rsp.token.as_ref().expect("token not parsed");
        assert_eq!("tokentokentokentokentokentokento", token);
        assert!(rsp.errors.is_none());

        Ok(())
    }

    #[test]
    fn json_deserialize_error() -> Result<(), Error> {
        let rsp: KtraResponse = serde_json::from_str(
            r#"{"errors":[{"detail":"the user identified 'ktra-secure-auth:test' already exists"}]}"#,
        )?;

        assert!(rsp.token.is_none());
        let errors = rsp.errors.as_ref().expect("errors not parsed");
        assert_eq!(1, errors.len());
        assert_eq!(
            "the user identified 'ktra-secure-auth:test' already exists",
            errors[0].detail,
        );

        Ok(())
    }
}
