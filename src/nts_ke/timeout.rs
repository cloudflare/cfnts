use std::cmp::{Ord, Ordering};

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
