use openai::context;

#[test]
fn test_preauth_cookie_provider() {
    let time = openai::now_duration().unwrap();
    let ctx = context::get_instance();
    ctx.push_preauth_cookie(&format!("id0:{}-xxx", time.as_secs()), Some(3600));
    ctx.push_preauth_cookie(&format!("id1:{}-yyy", time.as_secs()), Some(3600));
}
