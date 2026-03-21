use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::{Map, Value};

use crate::daemon;
use crate::protocol::{Request, Response};

#[derive(Parser, Debug)]
#[command(name = "agent-password")]
#[command(about = "Local password manager with shared approval session")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Vault(VaultCommand),
    Session(SessionCommand),
    Login(LoginCommand),
    Secret(SecretCommand),
    Secrets(SecretsCommand),
    Requests(RequestsCommand),
    Grants(GrantsCommand),
    #[command(hide = true, name = "__daemon")]
    Daemon,
}

#[derive(Args, Debug)]
struct VaultCommand {
    #[command(subcommand)]
    command: VaultSubcommand,
}

#[derive(Subcommand, Debug)]
enum VaultSubcommand {
    Init,
}

#[derive(Args, Debug)]
struct SessionCommand {
    #[command(subcommand)]
    command: SessionSubcommand,
}

#[derive(Args, Debug)]
struct LoginCommand {
    #[command(subcommand)]
    command: LoginSubcommand,
}

#[derive(Subcommand, Debug)]
enum LoginSubcommand {
    Add(LoginAddArgs),
}

#[derive(Args, Debug)]
struct LoginAddArgs {
    id: String,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    username: String,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Subcommand, Debug)]
enum SessionSubcommand {
    Create {
        #[arg(long)]
        replace: bool,
    },
    Status,
    Close,
    Clear,
}

#[derive(Args, Debug)]
struct SecretCommand {
    #[command(subcommand)]
    command: SecretSubcommand,
}

#[derive(Subcommand, Debug)]
enum SecretSubcommand {
    Put(SecretPutArgs),
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Delete {
        id: String,
    },
}

#[derive(Args, Debug)]
struct SecretPutArgs {
    id: String,
    #[arg(long = "type")]
    kind: String,
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    service: Option<String>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(long = "field", value_name = "KEY=VALUE")]
    fields: Vec<String>,
}

#[derive(Args, Debug)]
struct SecretsCommand {
    #[command(subcommand)]
    command: SecretsSubcommand,
}

#[derive(Subcommand, Debug)]
enum SecretsSubcommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Request {
        ids: Vec<String>,
        #[arg(long)]
        requester: String,
        #[arg(long)]
        reason: Option<String>,
    },
    Get {
        id: String,
        #[arg(long = "field")]
        fields: Vec<String>,
        #[arg(long)]
        env_file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args, Debug)]
struct RequestsCommand {
    #[command(subcommand)]
    command: RequestsSubcommand,
}

#[derive(Subcommand, Debug)]
enum RequestsSubcommand {
    List {
        #[arg(long)]
        json: bool,
    },
    Show {
        request_id: u64,
        #[arg(long)]
        json: bool,
    },
    Approve {
        request_id: u64,
        selection: String,
    },
    Deny {
        request_id: u64,
        selection: Option<String>,
    },
}

#[derive(Args, Debug)]
struct GrantsCommand {
    #[command(subcommand)]
    command: GrantsSubcommand,
}

#[derive(Subcommand, Debug)]
enum GrantsSubcommand {
    List {
        #[arg(long)]
        json: bool,
    },
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Daemon => daemon::run_daemon(),
        Command::Vault(command) => handle_vault(command),
        Command::Session(command) => handle_session(command),
        Command::Login(command) => handle_login(command),
        Command::Secret(command) => handle_secret(command),
        Command::Secrets(command) => handle_secrets(command),
        Command::Requests(command) => handle_requests(command),
        Command::Grants(command) => handle_grants(command),
    }
}

fn handle_vault(command: VaultCommand) -> Result<()> {
    match command.command {
        VaultSubcommand::Init => match daemon::send(&Request::VaultInit)? {
            Response::Ack { message } => {
                println!("{message}");
                Ok(())
            }
            Response::Error { message } => Err(anyhow!(message)),
            other => unexpected_response(other),
        },
    }
}

fn handle_session(command: SessionCommand) -> Result<()> {
    let response = match command.command {
        SessionSubcommand::Create { replace } => daemon::send(&Request::SessionCreate { replace })?,
        SessionSubcommand::Status => daemon::send(&Request::SessionStatus)?,
        SessionSubcommand::Close => daemon::send(&Request::SessionClose)?,
        SessionSubcommand::Clear => daemon::send(&Request::SessionClear)?,
    };

    match response {
        Response::Ack { message } => {
            println!("{message}");
            Ok(())
        }
        Response::SessionStatus { status } => {
            println!("exists: {}", status.exists);
            println!("unlocked: {}", status.unlocked);
            println!(
                "approved: {}",
                if status.approved_ids.is_empty() {
                    "<none>".into()
                } else {
                    status.approved_ids.join(", ")
                }
            );
            println!(
                "pending requests: {}",
                if status.pending_requests.is_empty() {
                    "<none>".into()
                } else {
                    status
                        .pending_requests
                        .iter()
                        .map(|id| id.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            Ok(())
        }
        Response::Error { message } => Err(anyhow!(message)),
        other => unexpected_response(other),
    }
}

fn handle_secret(command: SecretCommand) -> Result<()> {
    match command.command {
        SecretSubcommand::Put(args) => {
            let mut fields = parse_key_value_fields(&args.fields)?;
            if fields.is_empty() {
                return Err(anyhow!("at least one `--field key=value` is required"));
            }
            let response = daemon::send(&Request::SecretPut {
                id: args.id,
                kind: args.kind,
                title: args.title,
                service: args.service,
                username: args.username,
                tags: args.tags,
                fields: std::mem::take(&mut fields),
            })?;
            print_ack(response)
        }
        SecretSubcommand::Show { id, json } => match daemon::send(&Request::SecretShow { id })? {
            Response::SecretShow { secret } => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&secret)
                            .context("failed to encode secret metadata")?
                    );
                } else {
                    print_secret_metadata_row(&secret);
                }
                Ok(())
            }
            Response::Error { message } => Err(anyhow!(message)),
            other => unexpected_response(other),
        },
        SecretSubcommand::Delete { id } => print_ack(daemon::send(&Request::SecretDelete { id })?),
    }
}

fn handle_login(command: LoginCommand) -> Result<()> {
    match command.command {
        LoginSubcommand::Add(args) => {
            if !args.password_stdin {
                return Err(anyhow!(
                    "`agent-password login add` requires --password-stdin so secrets are not passed on the command line"
                ));
            }
            let password = read_stdin_string()?.trim_end_matches('\n').to_string();
            let mut fields = Map::new();
            fields.insert("username".into(), Value::String(args.username.clone()));
            fields.insert("password".into(), Value::String(password));
            if let Some(url) = &args.url {
                fields.insert("url".into(), Value::String(url.clone()));
            }
            let response = daemon::send(&Request::SecretPut {
                id: args.id,
                kind: "login".into(),
                title: args.title,
                service: args.url,
                username: Some(args.username),
                tags: args.tags,
                fields,
            })?;
            print_ack(response)
        }
    }
}

fn handle_secrets(command: SecretsCommand) -> Result<()> {
    match command.command {
        SecretsSubcommand::List { json } => match daemon::send(&Request::SecretsList)? {
            Response::SecretsList { secrets } => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&secrets)
                            .context("failed to encode secret list")?
                    );
                } else if secrets.is_empty() {
                    println!("no secrets");
                } else {
                    for secret in secrets {
                        print_secret_metadata_row(&secret);
                    }
                }
                Ok(())
            }
            Response::Error { message } => Err(anyhow!(message)),
            other => unexpected_response(other),
        },
        SecretsSubcommand::Request {
            ids,
            requester,
            reason,
        } => {
            if ids.is_empty() {
                return Err(anyhow!("at least one secret id is required"));
            }
            match daemon::send(&Request::SecretsRequest {
                ids,
                requester,
                reason,
            })? {
                Response::RequestCreated { request } => {
                    println!("created request {}", request.id);
                    println!("requester: {}", request.requester);
                    if !request.reason.is_empty() {
                        println!("reason: {}", request.reason);
                    }
                    println!("secrets: {}", request.secret_ids.join(", "));
                    Ok(())
                }
                Response::Error { message } => Err(anyhow!(message)),
                other => unexpected_response(other),
            }
        }
        SecretsSubcommand::Get {
            id,
            fields,
            env_file,
            json,
        } => match daemon::send(&Request::SecretsGet { id, fields })? {
            Response::SecretValues { secret_id, fields } => {
                if let Some(path) = env_file {
                    write_env_file(&path, &fields)?;
                    println!("wrote {}", path.display());
                    return Ok(());
                }
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&fields)
                            .context("failed to encode secret values")?
                    );
                    return Ok(());
                }
                println!("{secret_id}");
                for (field, value) in fields {
                    println!("{field}={value}");
                }
                Ok(())
            }
            Response::Error { message } => Err(anyhow!(message)),
            other => unexpected_response(other),
        },
    }
}

fn handle_requests(command: RequestsCommand) -> Result<()> {
    match command.command {
        RequestsSubcommand::List { json } => match daemon::send(&Request::RequestsList)? {
            Response::RequestsList { requests } => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&requests)
                            .context("failed to encode request list")?
                    );
                } else if requests.is_empty() {
                    println!("no pending requests");
                } else {
                    for request in requests {
                        println!(
                            "{} requester={} reason={} secrets={}",
                            request.id,
                            request.requester,
                            if request.reason.is_empty() {
                                "<none>"
                            } else {
                                &request.reason
                            },
                            request.secret_ids.join(", ")
                        );
                    }
                }
                Ok(())
            }
            Response::Error { message } => Err(anyhow!(message)),
            other => unexpected_response(other),
        },
        RequestsSubcommand::Show { request_id, json } => {
            match daemon::send(&Request::RequestsShow { request_id })? {
                Response::RequestShow { request, numbered } => {
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&(request, numbered))
                                .context("failed to encode request details")?
                        );
                    } else {
                        println!("request {}", request.id);
                        println!("requester: {}", request.requester);
                        println!(
                            "reason: {}",
                            if request.reason.is_empty() {
                                "<none>"
                            } else {
                                &request.reason
                            }
                        );
                        for secret in numbered {
                            println!(
                                "{}. {} [{}] title={} service={} username={} tags={}",
                                secret.index,
                                secret.metadata.id,
                                secret.metadata.kind,
                                secret.metadata.title,
                                if secret.metadata.service.is_empty() {
                                    "<none>"
                                } else {
                                    &secret.metadata.service
                                },
                                if secret.metadata.username.is_empty() {
                                    "<none>"
                                } else {
                                    &secret.metadata.username
                                },
                                if secret.metadata.tags.is_empty() {
                                    "<none>".into()
                                } else {
                                    secret.metadata.tags.join(",")
                                }
                            );
                        }
                    }
                    Ok(())
                }
                Response::Error { message } => Err(anyhow!(message)),
                other => unexpected_response(other),
            }
        }
        RequestsSubcommand::Approve {
            request_id,
            selection,
        } => print_ack(daemon::send(&Request::RequestsApprove {
            request_id,
            selection,
        })?),
        RequestsSubcommand::Deny {
            request_id,
            selection,
        } => print_ack(daemon::send(&Request::RequestsDeny {
            request_id,
            selection,
        })?),
    }
}

fn handle_grants(command: GrantsCommand) -> Result<()> {
    match command.command {
        GrantsSubcommand::List { json } => match daemon::send(&Request::GrantsList)? {
            Response::GrantsList { grants } => {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&grants).context("failed to encode grants")?
                    );
                } else if grants.is_empty() {
                    println!("no approved secrets");
                } else {
                    for grant in grants {
                        print_secret_metadata_row(&grant);
                    }
                }
                Ok(())
            }
            Response::Error { message } => Err(anyhow!(message)),
            other => unexpected_response(other),
        },
    }
}

fn print_ack(response: Response) -> Result<()> {
    match response {
        Response::Ack { message } => {
            println!("{message}");
            Ok(())
        }
        Response::Error { message } => Err(anyhow!(message)),
        other => unexpected_response(other),
    }
}

fn unexpected_response(response: Response) -> Result<()> {
    Err(anyhow!("unexpected daemon response: {response:?}"))
}

fn parse_key_value_fields(fields: &[String]) -> Result<Map<String, Value>> {
    let mut result = Map::new();
    for field in fields {
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| anyhow!("field `{field}` must be in KEY=VALUE form"))?;
        result.insert(key.to_owned(), Value::String(value.to_owned()));
    }
    Ok(result)
}

fn print_secret_metadata_row(secret: &crate::storage::SecretMetadata) {
    println!(
        "{} [{}] title={} service={} username={} tags={} updated_at={}",
        secret.id,
        secret.kind,
        secret.title,
        if secret.service.is_empty() {
            "<none>"
        } else {
            &secret.service
        },
        if secret.username.is_empty() {
            "<none>"
        } else {
            &secret.username
        },
        if secret.tags.is_empty() {
            "<none>".into()
        } else {
            secret.tags.join(",")
        },
        secret.updated_at
    );
}

fn write_env_file(path: &PathBuf, fields: &BTreeMap<String, String>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let mut content = String::new();
    for (field, value) in fields {
        let name = sanitize_env_name(field);
        content.push_str(&format!("{name}={}\n", shell_quote(value)));
    }
    fs::write(path, content).with_context(|| format!("failed to write {}", path.display()))
}

fn sanitize_env_name(field: &str) -> String {
    field
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn shell_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".into();
    }
    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn read_stdin_string() -> Result<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("failed to read stdin")?;
    Ok(buffer)
}
