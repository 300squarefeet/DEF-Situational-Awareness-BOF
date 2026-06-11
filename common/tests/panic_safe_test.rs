use common::try_catch;

fn risky(x: i32) -> Result<i32, &'static str> {
    if x < 0 { Err("negative") } else { Ok(x * 2) }
}

#[test]
fn try_catch_propagates_ok() {
    let r: Result<i32, &'static str> = try_catch!(risky(5));
    assert_eq!(r, Ok(10));
}

#[test]
fn try_catch_converts_err_to_static_str() {
    let r: Result<i32, &'static str> = try_catch!(risky(-1));
    assert_eq!(r, Err("negative"));
}
