use std::error::Error as StdError;
use std::fmt::{Display, Error as FmtError, Formatter};
use std::io::{stdout, Write};

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use curl::easy::{Easy, List};
use curl::Error as CurlError;
use log::*;

#[derive(Debug)]
enum Error {
    Curl(CurlError),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        match self {
            Self::Curl(e) => write!(f, "Curl error: {}", e),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Curl(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<CurlError> for Error {
    fn from(e: CurlError) -> Self {
        Self::Curl(e)
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
            Arg::with_name("server_addr")
                .short("a")
                .long("addr")
                .takes_value(true)
                .validator(server_addr_validator),
        )
        .subcommand(
            SubCommand::with_name("new")
                .arg(
                    Arg::with_name("user")
                        .takes_value(true)
                        .empty_values(false)
                        .required(true)
                        .validator(username_validator),
                )
                .arg(
                    Arg::with_name("pass")
                        .empty_values(true)
                        .required(true)
                        .validator(password_validator),
                ),
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
                .arg(
                    Arg::with_name("pass")
                        .empty_values(true)
                        .required(true)
                        .validator(password_validator),
                ),
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
                .arg(
                    Arg::with_name("old_pass")
                        .empty_values(true)
                        .required(true)
                        .validator(password_validator),
                )
                .arg(
                    Arg::with_name("new_pass")
                        .empty_values(true)
                        .required(true)
                        .validator(password_validator),
                ),
        )
        .get_matches();

    match matches.subcommand() {
        ("new", Some(sub_m)) => new_user(sub_m),
        ("login", Some(sub_m)) => login_user(sub_m),
        ("password", Some(sub_m)) => change_password(sub_m),
        (_, _) => panic!("subcommand not matched"),
    }
}

fn server_addr_validator(_server_name: String) -> Result<(), String> {
    // TODO:
    Ok(())
}

fn username_validator(_username: String) -> Result<(), String> {
    // TODO:
    Ok(())
}

fn password_validator(_password: String) -> Result<(), String> {
    // TODO:
    Ok(())
}

fn new_user(matches: &ArgMatches) -> Result<(), Error> {
    let user = matches.value_of("user").expect("no username set");
    let pass = matches.value_of("pass").expect("no password set");

    info!("new_user: user=\"{}\" pass=\"{}\"", user, pass);

    let mut handle = Easy::new();
    handle.url(&format!(
        "http://localhost:8000/ktra/api/v1/new_user/{}",
        user
    ))?;
    handle.post(true)?;
    let mut headers = List::new();
    headers.append("Content-Type: application/json")?;
    handle.http_headers(headers)?;
    handle.post_fields_copy(format!("{{\"password\":\"{}\"}}", pass).as_bytes())?;

    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            stdout().write_all(new_data).unwrap();
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }

    Ok(())
}

fn login_user(matches: &ArgMatches) -> Result<(), Error> {
    let user = matches.value_of("user").expect("no username set");
    let pass = matches.value_of("pass").expect("no password set");

    info!("login_user: user=\"{}\" pass=\"{}\"", user, pass);

    let mut handle = Easy::new();
    handle.url(&format!("http://localhost:8000/ktra/api/v1/login/{}", user))?;
    handle.post(true)?;
    let mut headers = List::new();
    headers.append("Content-Type: application/json")?;
    handle.http_headers(headers)?;
    handle.post_fields_copy(format!("{{\"password\":\"{}\"}}", pass).as_bytes())?;

    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            stdout().write_all(new_data).unwrap();
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }

    Ok(())
}

fn change_password(matches: &ArgMatches) -> Result<(), Error> {
    let user = matches.value_of("user").expect("no username set");
    let old_pass = matches.value_of("old_pass").expect("no password set");
    let new_pass = matches.value_of("new_pass").expect("no password set");

    info!(
        "change_password: user=\"{}\" old_pass=\"{}\" new_pass=\"{}\"",
        user, old_pass, new_pass
    );

    let mut handle = Easy::new();
    handle.url(&format!(
        "http://localhost:8000/ktra/api/v1/change_password/{}",
        user
    ))?;
    handle.post(true)?;
    let mut headers = List::new();
    headers.append("Content-Type: application/json")?;
    handle.http_headers(headers)?;
    handle.post_fields_copy(
        format!(
            "{{\"old_password\":\"{}\",\"new_password\":\"{}\"}}",
            old_pass, new_pass
        )
        .as_bytes(),
    )?;

    {
        let mut transfer = handle.transfer();
        transfer.write_function(|new_data| {
            stdout().write_all(new_data).unwrap();
            Ok(new_data.len())
        })?;
        transfer.perform()?;
    }

    Ok(())
}
