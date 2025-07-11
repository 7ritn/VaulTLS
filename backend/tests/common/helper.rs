use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn get_timestamp(from_now_in_years: u64) -> i64 {
    let time = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 365 * from_now_in_years);
    time.duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
}