#[test]
fn should_verify_rfc3164_accum() {
    use syslog_client::tracing::Rfc3164SpanAttrsAccum;

    let mut accum = Rfc3164SpanAttrsAccum::new("my_span");
    accum.record_debug_value(&"not-trunct");
    assert_eq!(accum.span_values(), "\"not-trunct\"");

    let big_value = "123456789-123456789-123456789-123456789-123456789";
    accum = Rfc3164SpanAttrsAccum::new("my_span");
    accum.record_debug_value(&big_value);
    assert_eq!(accum.span_values(), "<TRNCT>");

    let not_big_value = "123456789-123456789-123456789-123456789-123456789";
    accum = Rfc3164SpanAttrsAccum::new("my_span");
    accum.record_str_value(big_value);
    assert_eq!(accum.span_values(), not_big_value);

    let big_value = "123456789-123456789-123456789-123456789-123456789-1";
    accum = Rfc3164SpanAttrsAccum::new("my_span");
    accum.record_str_value(big_value);
    assert_eq!(accum.span_values(), "<TRNCT>");
}
