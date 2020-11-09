use bstr::ByteSlice;
use fs3::FileExt;
use std::{
    collections::HashMap,
    env, fs,
    io::{self, prelude::*, SeekFrom},
    process,
    result::Result,
    str,
};

use quick_error::quick_error;

fn main() -> Result<(), Error> {
    //let mut log = io::stderr();
    let home_dir = env::var("HOME")?;
    let mut log = fs::File::create(format!("{}/logs/proc-receive.log", home_dir))?;
    let _arg0 = process_args(&mut log);
    process_env(&mut log)?;
    process_stdin(&mut log)?;
    Ok(())
}

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Io(err: std::io::Error) {
            from()
        }
        Utf8Str(err: std::str::Utf8Error) {
           from()
        }
        HexParse(err: std::num::ParseIntError) {
            from()
        }
    HexDecode(err: hex::FromHexError) {
        from()
    }
        PushOptionsRequired
    EnvVar(err: std::env::VarError) {
        from()
    }
        ExpectedOID
        ExpectedRef
        ExpectedFlushPkt
        UnsupportedProtocolVersion(v: Option<String>) {
            from()
        }
        OverflowPullID
        InvalidSHA
    }
}

fn incr_pull_id(log: &mut dyn io::Write) -> Result<u64, Error> {
    let mut contents: [u8; 8] = [0; 8];
    write!(log, "open pull_id file\n")?;
    let mut f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open("info/pull_id.count")?;
    let () = f.lock_exclusive()?;


    // FIXME read_exact calls probably needs a timeout associated with it
    // for correctness to avoid a DOS. That may be covered by receive-pack
    // haven't checked, but at least while debugging it would be helpful.

    // If this fails, we likely just created the empty file and failed to read,
    // so contents is still [0; 8], and we write that to the file next.
    if let Ok(()) = f.read_exact(&mut contents) {
        ()
    }

    let id: u64 = u64::from_ne_bytes(contents);

    if let Some(id) = id.checked_add(1) {
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&id.to_ne_bytes())?;
        f.sync_all()?;
        f.unlock()?;
        drop(f);
        return Ok(id);
    } else {
        f.unlock()?;
        drop(f);
        return Err(crate::Error::OverflowPullID);
    }
}

fn process_env(log: &mut dyn std::io::Write) -> Result<(), Error> {
    if cfg!(feature = "log_env") {
        write!(log, "BEGIN env\n")?;
        for (key, value) in env::vars() {
            write!(log, "hook {}={}\n", key, value)?;
        }
        write!(log, "END env\n")?;
        log.flush()?;
    }

    Ok(())
}

fn process_args(log: &mut dyn std::io::Write) -> Result<String, Error> {
    let mut args = env::args();
    let process_name = args.next().unwrap();

    if cfg!(feature = "log_args") {
        let args: Vec<_> = args.collect();
        write!(log, "hook {} argv: {:?}\n", process_name, args)?;
    }

    Ok(process_name)
}

fn split_once<'a>(s: &'a str, delim: char) -> Option<(&'a str, &'a str)> {
    let pos = s.find(delim);
    pos.map(|idx| (&s[0..idx], &s[idx + delim.len_utf8()..]))
}

const FLUSH_PKT: &[u8] = b"0000";

fn read_version_push_options(
    stdin: &mut io::BufReader<io::Stdin>,
    _log: &mut dyn io::Write,
) -> Result<(), Error> {
    let mut sz_buf: [u8; 4] = [0; 4];
    stdin.read_exact(&mut sz_buf)?;

    let sz: usize = usize::from_str_radix(std::str::from_utf8(&sz_buf)?, 16)?;
    let mut buf = vec![0; sz - 4];
    stdin.read_exact(&mut buf)?;

    let s = std::str::from_utf8(buf.as_bytes())?;

    if let Some((version, rest)) = split_once(s, '=') {
        assert!(version == "version");
        if let Some((version_num, options)) = split_once(rest, '\0') {
            if version_num != "1" {
                return Err(Error::UnsupportedProtocolVersion(Some(
                    version_num.to_string(),
                )));
            }
            let mut found_push_option = false;
            for opt in options.split_ascii_whitespace() {
                if opt == "push-options" {
                    found_push_option = true
                }
            }

            if found_push_option == false {
                return Err(Error::PushOptionsRequired);
            } else {
                return Ok(());
            }
        } else {
            return Err(Error::UnsupportedProtocolVersion(None));
        }
    } else {
        return Err(Error::PushOptionsRequired);
    }
}

fn read_flush_pkt(stdin: &mut io::BufReader<io::Stdin>) -> Result<(), Error> {
    let mut flush_buf: [u8; 4] = [0; 4];
    stdin.read_exact(&mut flush_buf)?;
    if flush_buf == FLUSH_PKT {
        Ok(())
    } else {
        Err(Error::ExpectedFlushPkt)
    }
}

fn write_version_push_options(stdout: &mut io::Stdout) -> Result<(), Error> {
    stdout.write(b"001bversion=1\0push-options\n")?;
    stdout.write(FLUSH_PKT)?;
    Ok(stdout.flush()?)
}

fn read_commands(
    stdin: &mut io::BufReader<io::Stdin>,
    commands: &mut Vec<(String, String, String)>,
    _log: &mut dyn io::Write,
) -> Result<(), Error> {
    let mut sz_buf: [u8; 4] = [0; 4];
    Ok(loop {
        stdin.read_exact(&mut sz_buf)?;
        let s_szbuf = std::str::from_utf8(&sz_buf)?;
        let sz: usize = usize::from_str_radix(s_szbuf, 16)?;
        if sz == 0 {
            // Flush packet.
            break;
        }

        let mut buf = vec![0; sz - 4];
        stdin.read_exact(&mut buf)?;
        let s = std::str::from_utf8(buf.as_bytes())?;
        let mut command_iter = s.split_ascii_whitespace();
        if let Some(old_oid) = command_iter.next() {
            if let Some(new_oid) = command_iter.next() {
                if let Some(s_ref) = command_iter.next() {
                    // Check that it seems like a sha1
                    // This avoids shell commands embedded in untrusted input.
                    // just toss away the result, instead of converting it back
                    // into a string.
                    if old_oid.len() == 40 && new_oid.len() == 40 {
                        if let Ok(_) = hex::decode(old_oid) {
                            if let Ok(_) = hex::decode(new_oid) {
                                commands.push((
                                    old_oid.to_string(),
                                    new_oid.to_string(),
                                    s_ref.to_string(),
                                ));
                                continue;
                            }
                        }
                    }

                    return Err(Error::InvalidSHA);
                } else {
                    return Err(Error::ExpectedRef);
                }
            } else {
                return Err(Error::ExpectedOID);
            }
        } else {
            return Err(Error::ExpectedOID);
        }
    })
}

fn read_command_push_options(
    stdin: &mut io::BufReader<io::Stdin>,
    options: &mut HashMap<String, String>,
    _log: &mut dyn io::Write,
) -> Result<(), Error> {
    let mut sz_buf: [u8; 4] = [0; 4];
    Ok(loop {
        stdin.read_exact(&mut sz_buf)?;
        let sz: usize = usize::from_str_radix(std::str::from_utf8(&sz_buf)?, 16)?;
        if sz == 0 {
            // Flush packet.
            break;
        }

        let mut buf = vec![0; sz - 4];
        stdin.read_exact(&mut buf)?;

        let s = std::str::from_utf8(buf.as_bytes())?;
        if let Some((key, value)) = split_once(s, '=') {
            options.insert(key.to_string(), value.to_string());
        }
    })
}

fn update_refs(
    stdout: &mut io::Stdout,
    commands: &Vec<(String, String, String)>,
    log: &mut dyn io::Write,
) -> Result<(), Error> {
    // FIXME we actually need to put something else besides master here.
    // I.e. the actual branch
    let new_ref = format!("refs/heads/for/{branch}/pr{pull_id}", branch="master", pull_id=incr_pull_id(log)?);
    let mut args = ["update-ref", &new_ref, "0"];
    for (_old_oid, _new_oid, _s_ref) in commands.iter() {
        args[2] = _new_oid;
        let output = process::Command::new("git")
            .args(&args)
            .output()
            .expect("failed to update ref");
        assert!(output.status.success());
        stdout.write(
            format!(
                "{:04x}ok {}",
                _s_ref.len() + 4 + "ok".len() + " ".len(),
                _s_ref
            )
            .as_bytes(),
        )?;
        stdout.write(
            format!(
                "{:04x}option refname {}",
                new_ref.len() + 4 + "option refname".len() + " ".len(),
                new_ref
            )
            .as_bytes(),
        )?;
        stdout.write(
            format!(
                "{:04x}option old-oid {}",
                "option old-oid".len() + 4 + _old_oid.len() + " ".len(),
                _old_oid
            )
            .as_bytes(),
        )?;
        stdout.write(
            format!(
                "{:04x}option new-oid {}",
                "option new-oid".len() + 4 + _new_oid.len() + " ".len(),
                _new_oid
            )
            .as_bytes(),
        )?;
    }

    stdout.write(FLUSH_PKT.as_bytes())?;
    Ok(stdout.flush()?)
}

fn process_stdin(log: &mut dyn std::io::Write) -> Result<(), Error> {
    let mut w = io::stdout();
    let mut rbuf = std::io::BufReader::new(io::stdin());

    read_version_push_options(&mut rbuf, log)?;
    read_flush_pkt(&mut rbuf)?;
    write_version_push_options(&mut w)?;
    let mut commands: Vec<(String, String, String)> = Vec::new();
    read_commands(&mut rbuf, &mut commands, log)?;
    let mut options: HashMap<String, String> = HashMap::new();
    read_command_push_options(&mut rbuf, &mut options, log)?;
    update_refs(&mut w, &commands, log)
}
