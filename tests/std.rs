use core::time;
use std::io;
use std::sync::mpsc;

use syslog_client::syslog::header::{Tag, Hostname};
use syslog_client::writer::transport;
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
    let mut logger = Syslog::new(Facility::LOG_USER, HOSTNAME, TAG).rfc3164(transport::InMemory::<String>::new(sender)).with_buffer();
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

    let udp = transport::Udp {
        local_port: 65001,
        remote_addr: (transport::LOCAL_HOST, 5514).into(),
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

    let tcp = transport::Tcp {
        remote_addr: (transport::LOCAL_HOST, 5514).into(),
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
    use syslog_client::writer::transport::Unix;

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

#[cfg(feature = "log04")]
#[test]
fn should_generate_rfc3164_messages_log04() {
    use syslog_client::log04::Rfc3164Logger;

    const TAG: Tag = match Tag::new("log04") {
        Some(tag) => tag,
        None => panic!("not valid tag"),
    };
    const HOSTNAME: Hostname = match Hostname::new("in.log04") {
        Some(hostname) => hostname,
        None => panic!("not valid hostname"),
    };

    let (sender, receiver) = mpsc::channel();
    let syslog = Syslog::new(Facility::LOG_USER, HOSTNAME, TAG);
    let writer = transport::InMemory::<String>::new(sender);
    let logger = Rfc3164Logger::new(syslog, writer);

    let _ = log04::set_logger(Box::leak(Box::new(logger)));
    log04::set_max_level(log04::LevelFilter::Info);
    log04::info!("Some info log");

    let mut line = receiver.try_recv().expect("to have line");

    println!("line1={line}");
    let mut line_split = line.rsplitn(2, ':');
    let log = line_split.next().unwrap();
    let _header = line_split.next().unwrap();
    assert_eq!(log, " Some info log");

    log04::debug!("Should not show debug log");
    assert!(receiver.try_recv().is_err(), "Debug logs are filtered out");

    log04::warn!(error = "ERROR"; "Some warning log");
    line = receiver.try_recv().expect("to have line");
    println!("line2={line}");
    line_split = line.rsplitn(2, ':');
    let log = line_split.next().unwrap();
    let _header = line_split.next().unwrap();
    assert_eq!(log, " Some warning log [KV error=ERROR]");
}

#[cfg(feature = "tracing")]
#[test]
fn should_generate_rfc3164_messages_tracing() {
    use core::fmt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use syslog_client::tracing::Rfc3164Layer;

    #[tracing::instrument]
    fn my_span(key: &str, value: &(impl fmt::Debug + ?Sized)) {
        tracing::info!(?value, "EVENT(key={key})");
    }


    const TAG: Tag = match Tag::new("tracing") {
        Some(tag) => tag,
        None => panic!("not valid tag"),
    };
    const HOSTNAME: Hostname = match Hostname::new("in.tracing") {
        Some(hostname) => hostname,
        None => panic!("not valid hostname"),
    };

    let (sender, receiver) = mpsc::channel();
    let syslog = Syslog::new(Facility::LOG_USER, HOSTNAME, TAG);
    let writer = transport::InMemory::<String>::new(sender);
    let logger = Rfc3164Layer::new(syslog, writer);

    let _guard = tracing_subscriber::registry().with(logger).set_default();
    tracing::info!("Some info log");

    let mut line = receiver.try_recv().expect("to have line");

    println!("line1={line}");
    let mut line_split = line.rsplitn(2, ':');
    let log = line_split.next().unwrap();
    let _header = line_split.next().unwrap();
    assert_eq!(log, " Some info log");

    tracing::warn!(error = "ERROR", "Some warning log");
    line = receiver.try_recv().expect("to have line");
    println!("line2={line}");
    line_split = line.rsplitn(2, ':');
    let log = line_split.next().unwrap();
    let _header = line_split.next().unwrap();
    assert_eq!(log, " Some warning log error=ERROR");

    my_span("test", "value");
    line = receiver.try_recv().expect("to have line");
    println!("line3={line}");
    line_split = line.rsplitn(2, ':');
    let log = line_split.next().unwrap();
    let _header = line_split.next().unwrap();
    #[cfg(not(feature = "tracing-full"))]
    assert_eq!(log, " EVENT(key=test) value=\"value\"");
    #[cfg(feature = "tracing-full")]
    assert_eq!(log, " EVENT(key=test) value=\"value\" [my_span key=test value=\"value\"]");
}
