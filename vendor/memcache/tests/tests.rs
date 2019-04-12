extern crate memcache;
extern crate rand;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::iter;
use std::thread;
use std::thread::JoinHandle;
use std::time;

fn gen_random_key() -> String {
    return iter::repeat(())
        .map(|()| thread_rng().sample(Alphanumeric))
        .take(10)
        .collect::<String>();
}

#[test]
fn test() {
    let mut urls = vec![
        "memcache://localhost:12346?tcp_nodelay=true",
        "memcache://localhost:12347?timeout=10",
        "memcache://localhost:12348",
        "memcache://localhost:12349",
    ];
    if cfg!(unix) {
        urls.push("memcache:///tmp/memcached2.sock");
    }
    let mut client = memcache::Client::connect(urls).unwrap();

    client.version().unwrap();

    client.set("foo", "bar", 0).unwrap();
    client.flush().unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, None);

    client.set("foo", "bar", 0).unwrap();
    client.flush_with_delay(3).unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, Some(String::from("bar")));
    thread::sleep(time::Duration::from_secs(4));
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, None);

    let mut keys: Vec<String> = Vec::new();
    for _ in 0..1000 {
        let key = gen_random_key();
        keys.push(key.clone());
        client.set(key.as_str(), "xxx", 0).unwrap();
    }

    for key in keys {
        let value: String = client.get(key.as_str()).unwrap().unwrap();
        assert_eq!(value, "xxx");
    }
}

#[test]
fn udp_test() {
    let urls = vec!["memcache+udp://localhost:22345"];
    let mut client = memcache::Client::connect(urls).unwrap();

    client.version().unwrap();

    client.set("foo", "bar", 0).unwrap();
    client.flush().unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, None);

    client.set("foo", "bar", 0).unwrap();
    client.flush_with_delay(3).unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, Some(String::from("bar")));
    thread::sleep(time::Duration::from_secs(4));
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, None);

    client.set("foo", "bar", 0).unwrap();
    let value = client.add("foo", "baz", 0);
    assert_eq!(value.is_err(), true);

    client.delete("foo").unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, None);

    client.add("foo", "bar", 0).unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, Some(String::from("bar")));

    client.replace("foo", "baz", 0).unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, Some(String::from("baz")));

    client.append("foo", "bar").unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, Some(String::from("bazbar")));

    client.prepend("foo", "bar").unwrap();
    let value: Option<String> = client.get("foo").unwrap();
    assert_eq!(value, Some(String::from("barbazbar")));

    client.set("fooo", 0, 0).unwrap();
    client.increment("fooo", 1).unwrap();
    let value: Option<String> = client.get("fooo").unwrap();
    assert_eq!(value, Some(String::from("1")));

    client.decrement("fooo", 1).unwrap();
    let value: Option<String> = client.get("fooo").unwrap();
    assert_eq!(value, Some(String::from("0")));

    assert_eq!(client.touch("foooo", 123).unwrap(), false);
    assert_eq!(client.touch("fooo", 12345).unwrap(), true);

    // gets is not supported for udp
    let value: Result<std::collections::HashMap<String, String>, _> = client.gets(vec!["foo", "fooo"]);
    assert_eq!(value.is_ok(), false);

    let mut keys: Vec<String> = Vec::new();
    for _ in 0..1000 {
        let key = gen_random_key();
        keys.push(key.clone());
        client.set(key.as_str(), "xxx", 0).unwrap();
    }

    for key in keys {
        let value: String = client.get(key.as_str()).unwrap().unwrap();

        assert_eq!(value, "xxx");
    }

    // test with multiple udp connections
    let mut handles: Vec<Option<JoinHandle<_>>> = Vec::new();
    for i in 0..10 {
        handles.push(Some(thread::spawn(move || {
            let key = format!("key{}", i);
            let value = format!("value{}", i);
            let mut client = memcache::Client::connect("memcache://localhost:22345?udp=true").unwrap();
            for j in 0..50 {
                let value = format!("{}{}", value, j);
                client.set(key.as_str(), value.clone(), 0).unwrap();
                let result: Option<String> = client.get(key.as_str()).unwrap();
                assert_eq!(result, Some(value.clone()));

                let result = client.add(key.as_str(), value.clone(), 0);
                assert_eq!(result.is_err(), true);

                client.delete(key.as_str()).unwrap();
                let result: Option<String> = client.get(key.as_str()).unwrap();
                assert_eq!(result, None);

                client.add(key.as_str(), value.clone(), 0).unwrap();
                let result: Option<String> = client.get(key.as_str()).unwrap();
                assert_eq!(result, Some(value.clone()));

                client.replace(key.as_str(), value.clone(), 0).unwrap();
                let result: Option<String> = client.get(key.as_str()).unwrap();
                assert_eq!(result, Some(value.clone()));

                client.append(key.as_str(), value.clone()).unwrap();
                let result: Option<String> = client.get(key.as_str()).unwrap();
                assert_eq!(result, Some(format!("{}{}", value, value)));

                client.prepend(key.as_str(), value.clone()).unwrap();
                let result: Option<String> = client.get(key.as_str()).unwrap();
                assert_eq!(result, Some(format!("{}{}{}", value, value, value)));
            }
        })));
    }

    for i in 0..10 {
        handles[i].take().unwrap().join().unwrap();
    }
}
