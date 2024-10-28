use syslog_client::syslog::header;
use syslog_client::Hostname;

#[test]
fn should_verify_header_tag_ctor() {
    assert!(header::Tag::new("").is_none());

    let mut text = String::new();
    for idx in 0..32 {
        text.push(char::from(b'a' + idx % 9));
        let tag = header::Tag::new(&text).expect("to create tag");
        assert_eq!(text, tag.as_str());
    }
    text.push('z');
    assert!(header::Tag::new(&text).is_none());
}

#[test]
fn should_generate_rfc3164_header() {
    let mut hostname = String::new();
    for idx in 0..64 {
        hostname.push((b'a' + idx % 9) as char);
    }
    let hostname = Hostname::new(&hostname).expect("to create 64 long hostname");

    let mut tag = String::new();
    for idx in 0..32 {
        tag.push((b'a' + idx % 9) as char);
    }
    let tag = header::Tag::new(&tag).expect("to create 32 long hostname");

    let header = header::Rfc3164 {
        pri: u8::MAX,
        timestamp: header::Timestamp {
            year: 2024,
            month: 0,
            day: 1,
            sec: 59,
            min: 59,
            hour: 24,
        },
        hostname: &hostname,
        tag: &tag,
        pid: u32::MAX,
    };
    let buffer = header.create_buffer();
    assert_eq!(buffer, "<255>Jan  1 24:59:59 abcdefghiabcdefghiabcdefghiabcdefghiabcdefghiabcdefghiabcdefghia abcdefghiabcdefghiabcdefghiabcde[4294967295]:");
}
