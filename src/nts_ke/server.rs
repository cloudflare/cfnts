use lazy_static::lazy_static;
use prometheus::{opts, register_counter, register_int_counter, IntCounter};

use std::cmp::{Ord, Ordering};

lazy_static! {
    static ref QUERY_COUNTER: IntCounter =
        register_int_counter!("nts_queries_total", "Number of NTS requests").unwrap();
    static ref ERROR_COUNTER: IntCounter =
        register_int_counter!("nts_errors_total", "Number of errors").unwrap();
    static ref TIMEOUT_COUNTER: IntCounter =
        register_int_counter!("nts_timeouts_total", "Number of connections that time out").unwrap();
}

/// We store timeouts in a heap. This structure contains the deadline
/// and the token by which the connection is identified.
#[derive(Eq)]
pub struct Timeout {
    pub deadline: u64,
    pub token: mio::Token,
}

impl Ord for Timeout {
    fn cmp(&self, other: &Timeout) -> Ordering {
        other.deadline.cmp(&self.deadline) // Reversed to make a min heap
    }
}

impl PartialOrd for Timeout {
    fn partial_cmp(&self, other: &Timeout) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Timeout {
    fn eq(&self, other: &Timeout) -> bool {
        self.deadline == other.deadline
    }
}
