use core::time;
use std::io;
use std::sync::mpsc;

use syslog_client::syslog::header::{Tag, Hostname};
use syslog_client::writer::{InMemory, Udp, Tcp, LOCAL_HOST};
use syslog_client::{Facility, Severity, Syslog};

#[test]
fn should_generate_rfc3164_messages_in_memory() {
    const TAG: Tag = match Tag::new("inmemory") {
        Some(tag) => tag,
        None => panic!("not valid tag"),
    };
    const HOSTNAME: Hostname = match Hostname::new("in.memory") {
        Some(hostname) => hostname,
        None => panic!("not valid hostname"),
    };

    let (sender, receiver) = mpsc::channel();
    let mut logger = Syslog::new(Facility::LOG_USER, HOSTNAME, TAG).rfc3164(InMemory::<String>::new(sender)).with_buffer();
    logger.write_str(Severity::LOG_ERR, "my error").expect("Success");

    let mut line = receiver.try_recv().expect("to have line");

    println!("line={line}");
    let mut line_split = line.rsplitn(2, ':');
    let log = line_split.next().unwrap();
    let header = line_split.next().unwrap();
    let header_size = header.len() + 2;
    assert_eq!(log, " my error");

    let chunk1_size = 1024 - header_size;
    println!("chunk1_size={chunk1_size}");

    //check split behavior
    let mut message = "1".repeat(chunk1_size);
    message.push('0');

    logger.write_str(Severity::LOG_ERR, &message).expect("Success");

    line = receiver.try_recv().expect("to have line 1");
    println!("line1={line}");
    let mut line_split = line.rsplitn(2, ':');
    let log = line_split.next().unwrap().trim_start();
    assert_eq!(log, &message[..chunk1_size]);

    line = receiver.try_recv().expect("to have line 2");
    println!("line2={line}");
    assert!(line.ends_with(": 0"));
}

#[test]
fn should_generate_rfc3164_messages_udp() {
    const TAG: Tag = match Tag::new("udp") {
        Some(tag) => tag,
        None => panic!("not valid tag"),
    };
    const HOSTNAME: Hostname = match Hostname::new("in.udp") {
        Some(hostname) => hostname,
        None => panic!("not valid hostname"),
    };

    let udp = Udp {
        local_port: 65001,
        remote_addr: (LOCAL_HOST, 5514).into(),
    };

    let mut logger = Syslog::new(Facility::LOG_USER, HOSTNAME, TAG).rfc3164(udp).with_buffer();
    logger.write_str(Severity::LOG_ERR, "my udp error").expect("Success");
}

#[test]
fn should_generate_rfc3164_messages_tcp() {
    const TAG: Tag = match Tag::new("tcp") {
        Some(tag) => tag,
        None => panic!("not valid tag"),
    };
    const HOSTNAME: Hostname = match Hostname::new("in.tcp") {
        Some(hostname) => hostname,
        None => panic!("not valid hostname"),
    };

    let tcp = Tcp {
        remote_addr: (LOCAL_HOST, 5514).into(),
        timeout: Some(time::Duration::from_secs(5)),
    };

    let mut logger = Syslog::new(Facility::LOG_USER, HOSTNAME, TAG).rfc3164(tcp).with_buffer();
    if let Err(error) = logger.write_str(Severity::LOG_ERR, "my tcp error") {
        //This test is used locally mostly so if connection refused do nothing
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }
}

#[cfg(unix)]
#[test]
fn should_generate_rfc3164_messages_unix() {
    use syslog_client::writer::Unix;

    const TAG: Tag = match Tag::new("unix") {
        Some(tag) => tag,
        None => panic!("not valid tag"),
    };
    const HOSTNAME: Hostname = match Hostname::new("in.unix") {
        Some(hostname) => hostname,
        None => panic!("not valid hostname"),
    };

    //All unix systems should have it, right?
    let unix = Unix::new_system().expect("Find syslog socket");
    let mut logger = Syslog::new(Facility::LOG_USER, HOSTNAME, TAG).rfc3164(unix).with_buffer();
    logger.write_str(Severity::LOG_ERR, "my unix error").expect("Successfully write");
}
