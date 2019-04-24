//! Filter records by matching some of their keys against a sets of values while allowing
//! for records of level high enough to pass. It also can apply a negative filter after the
//! positive filter to allow sophisticated 'hole-punching' into a matching category. Ultimately,
//! the resulting message (without keys and values) can be constrained by both presence of a regex
//! or its absence.

#[cfg(test)]
#[macro_use]
extern crate slog;

#[cfg(not(test))]
extern crate slog;

extern crate regex;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::option::Option;
use std::panic::UnwindSafe;
use std::panic::RefUnwindSafe;
use std::fmt::format;

use slog::KV;
use regex::Regex;

// @todo: must that be thread-safe?
struct FilteringSerializer<'a> {
    pending_matches: KVFilterListFlyWeight<'a>,
    tmp_str: String,
}

impl<'a> slog::Serializer for FilteringSerializer<'a> {
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments) -> slog::Result {
        if self.pending_matches.is_empty() {
            return Ok(());
        }

        let matched = if let Some(keyvalues) = self.pending_matches.get(&key) {
            self.tmp_str.clear();
            fmt::write(&mut self.tmp_str, *val)?;

            keyvalues.contains(&self.tmp_str)
        } else {
            false
        };

        if matched {
            self.pending_matches.remove(&key);
        }

        Ok(())
    }
}

/// Must be a hashmap since we do not rely on ordered keys
pub type KVFilterList = HashMap<String, HashSet<String>>;

/// flyweight copy that is created upfront and given to every serializer
type KVFilterListFlyWeight<'a> = HashMap<&'a str, &'a HashSet<String>>;

/// `Drain` filtering records using list of keys and values they
/// must have unless they are of a higher level than filtering applied.
/// it can apply a negative filter as well that overrides any matches but
/// will let higher level than filtering applied as well.
///
/// This `Drain` filters a log entry on a filtermap
/// that holds the key name in question and acceptable values
/// Key values are gathered up the whole hierarchy of inherited
/// loggers.
///
/// Example
/// =======
///
/// Logger( ... ; o!("thread" => "100");
/// log( ... ; "packet" => "send");
/// log( ... ; "packet" => "receive");
///
/// can be filtered on a map containing "thread" key component. If the
/// values contain "100" the log will be output, otherwise filtered.
/// The filtering map can contain further key "packet" and value "send".
/// With that the output for "receive" would be filtered.
///
/// More precisely
///
///   * a key is ignored until present in `filters`, otherwise an entry must
///     match for all the keys present in `filters` for any of the values given
///     for the key to pass the filter.
///   * an entry that hits any value of any negative filter key is filtered, this
///     takes precedence over `filters`
///   * Behavior of empty `KVFilterList` is undefined but normally anything should pass.
///   * Behavior of `KVFilter` that has same key in both the matching and the suppressing
///     section is undefined even if we have different values there. Logically, it should
///     be matching the positive and pass and only suppress negative if it finds matching
///     value but it's untested.
///
/// Additionally, the resulting message (without keys and values) can be constrained
/// by both presence of a regex or its absence by applying the `only_pass_on_regex`
/// and `always_suppress_on_regex` API calls. As the names suggest, suppression wins
/// if both regex's are set.
///
/// Usage
/// =====
///
/// Filtering in large systems that consist of multiple threads of same
/// code or have functionality of interest spread across many components,
/// modules, such as e.g. "sending packet" or "running FSM".
pub struct KVFilter<D: slog::Drain> {
    drain: D,
    filters: Option<KVFilterList>,
    neg_filters: Option<KVFilterList>,
    level: slog::Level,
    regex: Option<Regex>,
    neg_regex: Option<Regex>,
}

impl<D: slog::Drain> UnwindSafe for KVFilter<D> {}
impl<D: slog::Drain> RefUnwindSafe for KVFilter<D> {}

impl<'a, D: slog::Drain> KVFilter<D> {
    /// Create `KVFilter` letting e'thing pass unless filters are set. Anything more
    /// important than `level` will pass in any case.
    ///
    /// * `drain` - drain to be sent to
    /// * `level` - maximum level filtered, higher levels pass by without filtering
    pub fn new(drain: D, level: slog::Level) -> Self {
        KVFilter {
            drain: drain,
            level: level,
            filters: None,
            neg_filters: None,
            regex: None,
            neg_regex: None,
        }
    }

    /// pass through entries with all keys with _any_ of the matching values in its entries
    /// or ignore condition if None
    pub fn only_pass_any_on_all_keys(mut self, filters: Option<KVFilterList>) -> Self {
        self.filters = filters;
        self
    }

    /// suppress _any_ key with _any_ of the matching values in its entries or ignore
    /// condition if None.
    /// @note: This takes precedence over `only_pass_any`
    pub fn always_suppress_any(mut self, filters: Option<KVFilterList>) -> Self {
        self.neg_filters = filters;
        self
    }

    /// only pass when this regex is found in the log message output.
    pub fn only_pass_on_regex(mut self, regex: Option<Regex>) -> Self {
        self.regex = regex;
        self
    }

    /// suppress output if this regex if found in the log message output.
    pub fn always_suppress_on_regex(mut self, regex: Option<Regex>) -> Self {
        self.neg_regex = regex;
        self
    }

    fn is_match(&self, record: &slog::Record, logger_values: &slog::OwnedKVList) -> bool {
        // Can't use chaining here, as it's not possible to cast
        // SyncSerialize to Serialize
        let mut ser = FilteringSerializer {
            pending_matches: self.filters.as_ref().map_or(HashMap::new(), |f| {
                f.iter().map(|(k, v)| (k.as_str(), v)).collect()
            }),
            tmp_str: String::new(),
        };

        let mut negser = FilteringSerializer {
            pending_matches: self.neg_filters.as_ref().map_or(HashMap::new(), |ref f| {
                f.iter().map(|(k, v)| (k.as_str(), v)).collect()
            }),
            tmp_str: String::new(),
        };

        record.kv().serialize(record, &mut ser).unwrap();

        // negative we have to go all way down to check for _any_ key match
        record.kv().serialize(record, &mut negser).unwrap();
        logger_values.serialize(record, &mut negser).unwrap();

        let anynegativematch = ||
            negser.pending_matches.len() == self.neg_filters.as_ref()
                .map_or(0,
                        |m| m.keys().len());

        let mut pass = if ser.pending_matches.is_empty() {
            // if e'thing matched on the positive make sure _nothing_ matched on negative
            anynegativematch()
        } else {
            // check inside whether we find more matches
            logger_values.serialize(record, &mut ser).unwrap();

            if ser.pending_matches.is_empty() {
                anynegativematch()
            } else {
                false
            }
        };

        if pass && (self.regex.is_some() || self.neg_regex.is_some()) {
            let res = format(*record.msg());

            if let Some(ref posmatch) = self.regex {
                pass = posmatch.is_match(&res);
            };

            if pass {
                if let Some(ref negmatch) = self.neg_regex {
                    pass = !negmatch.is_match(&res);
                }
            }
        }

        pass
    }
}

impl<'a, D: slog::Drain> slog::Drain for KVFilter<D> {
    type Err = D::Err;
    type Ok = Option<D::Ok>;

    fn log(
        &self,
        info: &slog::Record,
        logger_values: &slog::OwnedKVList,
    ) -> Result<Self::Ok, Self::Err> {
        // println!("{:#?}", info.msg());

        if info.level() < self.level || self.is_match(info, logger_values) {
            self.drain.log(info, logger_values).map(Some)
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KVFilter;
    use slog::{Drain, Level, Logger, OwnedKVList, Record};
    use regex::Regex;
    use std::collections::HashSet;
    use std::iter::FromIterator;
    use std::sync::Mutex;
    use std::fmt::Display;
    use std::fmt::Formatter;
    use std::fmt::Result as FmtResult;
    use std::io;
    use std::sync::Arc;

    const YES: &'static str = "YES";
    const NO: &'static str = "NO";

    #[derive(Debug)]
    struct StringDrain {
        output: Arc<Mutex<Vec<String>>>,
    }

    /// seriously hacked logger drain that just counts messages to make
    /// sure we have tests behaving correcly
    impl<'a> Drain for StringDrain {
        type Err = io::Error;
        type Ok = ();

        fn log(&self, info: &Record, _: &OwnedKVList) -> io::Result<()> {
            let mut lo = self.output.lock().unwrap();
            let fmt = format!("{:?}", info.msg());

            if !fmt.contains(YES) && !fmt.contains(NO) {
                panic!(fmt);
            }

            (*lo).push(fmt);

            Ok(())
        }
    }

    impl<'a> Display for StringDrain {
        fn fmt(&self, f: &mut Formatter) -> FmtResult {
            write!(f, "none")
        }
    }

    fn testkvfilter<D: Drain>(d: D) -> KVFilter<D> {
        KVFilter::new(d, Level::Info).only_pass_any_on_all_keys(Some(
            vec![
                (
                    "thread".to_string(),
                    HashSet::from_iter(vec!["100".to_string(), "200".to_string()]),
                ),
                (
                    "direction".to_string(),
                    HashSet::from_iter(vec!["send".to_string(), "receive".to_string()]),
                ),
            ].into_iter()
                .collect(),
        ))
    }

    fn testnegkvfilter<D: Drain>(f: KVFilter<D>) -> KVFilter<D> {
        f.always_suppress_any(Some(
            vec![
                (
                    "deepcomp".to_string(),
                    HashSet::from_iter(vec!["1".to_string(), "2".to_string()]),
                ),
                (
                    "deepercomp".to_string(),
                    HashSet::from_iter(vec!["4".to_string(), "5".to_string()]),
                ),
            ].into_iter()
                .collect(),
        ))
    }

    #[test]
    /// get an asserting Drain, get a couple of loggers that
    /// have different nodes, components and see whether filtering
    /// is applied properly on the derived `Logger` copies
    fn nodecomponentlogfilter() {
        assert!(Level::Critical < Level::Warning);

        let out = Arc::new(Mutex::new(vec![]));

        let drain = StringDrain {
            output: out.clone(),
        };

        // build some small filter
        let filter = testkvfilter(drain);

        // Get a root logger that will log into a given drain.
        let mainlog = Logger::root(filter.fuse(), o!("version" => env!("CARGO_PKG_VERSION")));
        let sublog = mainlog.new(o!("thread" => "200", "sub" => "sub"));
        let subsublog = sublog.new(o!("direction" => "send"));
        let subsubsublog = subsublog.new(o!());

        let wrongthread = mainlog.new(o!("thread" => "400", "sub" => "sub"));

        info!(mainlog, "NO: filtered, main, no keys");
        info!(mainlog, "YES: unfiltered, on of thread matches, direction matches";
        "thread" => "100", "direction" => "send");
        info!(mainlog,
              "YES: unfiltered, on of thread matches, direction matches, different key order";
        "direction" => "send", "thread" => "100");

        warn!(mainlog, "YES: unfiltered, higher level"); // level high enough to pass anyway

        debug!(mainlog, "NO: filtered, level to low, no keys"); // level low

        info!(mainlog, "NO: filtered, wrong thread on record";
        "thread" => "300", "direction" => "send");

        info!(wrongthread, "NO: filtered, wrong thread on sublog");

        info!(sublog, "NO: filtered sublog, missing dirction ");

        info!(sublog, "YES: unfiltered sublog with added directoin";
        "direction" => "receive");

        info!(
            subsubsublog,
            "YES: unfiltered subsubsublog, direction on subsublog, thread on sublog"
        );

        // test twice same keyword with right value will give filter match
        let stackedthreadslog = wrongthread.new(o!("thread" => "200"));

        info!(stackedthreadslog,
              "YES: unfiltered since one of the threads matches from inherited";
        "direction" => "send");

        println!("resulting output: {:#?}", *out.lock().unwrap());

        assert_eq!(out.lock().unwrap().len(), 6);
    }

    #[test]
    /// get an asserting Drain, get a couple of loggers that
    /// have different nodes, components and deep/deeper components and see whether filtering
    /// is applied properly on the derived `Logger` copies while punching holes for the disallowed
    /// values
    fn negnodecomponentlogfilter() {
        assert!(Level::Critical < Level::Warning);

        let out = Arc::new(Mutex::new(vec![]));

        let drain = StringDrain {
            output: out.clone(),
        };

        // build some small filter
        let filter = testnegkvfilter(testkvfilter(drain.fuse()));

        // Get a root logger that will log into a given drain.
        let mainlog = Logger::root(filter.fuse(), o!("version" => env!("CARGO_PKG_VERSION")));
        let sublog = mainlog.new(o!("thread" => "200", "sub" => "sub"));
        let subsublog = sublog.new(o!("direction" => "send"));
        // deep match won't match
        let subsubsublog = subsublog.new(o!("deepcomp" => "0"));
        // deep match will filter
        let negsubsubsublog = subsublog.new(o!("deepcomp" => "1"));

        info!(mainlog, "NO: filtered, main, no keys");
        info!(mainlog, "YES: unfiltered, on of thread matches, direction matches";
        "thread" => "100", "direction" => "send");
        info!(subsubsublog, "YES: unfiltered, on of thread matches, direction matches, deep doesn't apply";
        "thread" => "100", "direction" => "send");
        info!(negsubsubsublog, "NO: filtered, on of thread matches, direction matches, deep negative applies";
        "thread" => "100", "direction" => "send");
        info!(subsubsublog, "NO: filtered, on of thread matches, direction matches, deep doesn't apply but deeper does";
        "thread" => "100", "direction" => "send", "deepercomp" => "4");
        info!(subsubsublog, "YES: unfiltered, on of thread matches, direction matches, deep doesn't apply and deeper doesn't";
        "thread" => "100", "direction" => "send", "deepercomp" => "7");

        println!("resulting output: {:#?}", *out.lock().unwrap());

        assert_eq!(out.lock().unwrap().len(), 3);
    }

    #[test]
    /// test negative and positive
    fn regextest() {
        assert!(Level::Critical < Level::Warning);

        let out = Arc::new(Mutex::new(vec![]));

        let drain = StringDrain {
            output: out.clone(),
        };

        // build some small filter
        let filter = KVFilter::new(drain.fuse(), Level::Info)
            .only_pass_on_regex(Some(Regex::new(r"PASS\d:").unwrap()))
            .always_suppress_on_regex(Some(Regex::new(r"NOPE\d:").unwrap()));

        // Get a root logger that will log into a given drain.
        let mainlog = Logger::root(filter.fuse(), o!("version" => env!("CARGO_PKG_VERSION")));

        info!(mainlog, "NO: filtered, no positive");
        info!(mainlog, "NO: NOPE2 PASS0 filtered, negative");
        info!(mainlog, "NO: filtered, no positive");
        info!(mainlog, "YES: PASS2: not filtered, positive");
        info!(mainlog, "YES: {}: not filtered, positive", "PASS4");

        println!("resulting output: {:#?}", *out.lock().unwrap());

        assert_eq!(out.lock().unwrap().len(), 2);
    }
}
