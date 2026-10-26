//! Bounded refresh policy for an owned display token.

pub(super) fn query_cached<T, V, E>(
    cache: &mut Option<T>,
    mut acquire: impl FnMut() -> Result<T, E>,
    mut query: impl FnMut(&T) -> Result<V, E>,
) -> Result<V, E> {
    if cache.is_none() {
        *cache = Some(acquire()?);
    }
    match query(cache.as_ref().expect("display token acquired")) {
        Ok(value) => Ok(value),
        Err(_) => {
            // Release the stale binder owner before asking for its replacement.
            drop(cache.take());
            *cache = Some(acquire()?);
            let result = query(cache.as_ref().expect("replacement display token acquired"));
            if result.is_err() {
                drop(cache.take());
            }
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::query_cached;
    use std::cell::RefCell;
    use std::rc::Rc;

    type Events = Rc<RefCell<Vec<String>>>;

    struct Token(u32, Events);

    impl Drop for Token {
        fn drop(&mut self) {
            self.1.borrow_mut().push(format!("drop:{}", self.0));
        }
    }

    fn token(id: u32, events: &Events) -> Token {
        events.borrow_mut().push(format!("acquire:{id}"));
        Token(id, Rc::clone(events))
    }

    fn query(value: &Token) -> Result<u32, &'static str> {
        value.1.borrow_mut().push(format!("query:{}", value.0));
        Ok(value.0)
    }

    #[test]
    fn consecutive_successes_reuse_one_owned_token_and_drop_once() {
        let events = Events::default();
        let mut cache = None;
        for _ in 0..3 {
            assert_eq!(
                query_cached(&mut cache, || Ok(token(1, &events)), query),
                Ok(1)
            );
        }
        drop(cache.take());
        assert_eq!(
            *events.borrow(),
            ["acquire:1", "query:1", "query:1", "query:1", "drop:1"]
        );
    }

    #[test]
    fn failed_query_releases_old_owner_before_one_reacquisition() {
        let events = Events::default();
        let mut cache = Some(token(1, &events));
        let result = query_cached(
            &mut cache,
            || Ok(token(2, &events)),
            |value| {
                query(value)?;
                if value.0 == 1 {
                    Err("stale display")
                } else {
                    Ok(value.0)
                }
            },
        );
        assert_eq!(result, Ok(2));
        assert_eq!(
            *events.borrow(),
            ["acquire:1", "query:1", "drop:1", "acquire:2", "query:2"]
        );
        drop(cache);
        assert_eq!(events.borrow().last().map(String::as_str), Some("drop:2"));
    }

    #[test]
    fn failed_reacquisition_leaves_no_cached_owner_for_the_next_frame() {
        let events = Events::default();
        let mut cache = Some(token(1, &events));
        let result = query_cached(
            &mut cache,
            || Err("no display token"),
            |value| {
                query(value)?;
                Err::<u32, _>("stale display")
            },
        );
        assert_eq!(result, Err("no display token"));
        assert!(cache.is_none());
        assert_eq!(*events.borrow(), ["acquire:1", "query:1", "drop:1"]);
        assert_eq!(
            query_cached(&mut cache, || Ok(token(3, &events)), query),
            Ok(3)
        );
    }

    #[test]
    fn two_invalid_queries_are_bounded_and_discard_both_tokens() {
        let events = Events::default();
        let mut cache = None;
        let mut next = 0;
        let result = query_cached(
            &mut cache,
            || {
                next += 1;
                Ok(token(next, &events))
            },
            |value| {
                query(value)?;
                Err::<u32, _>("invalid geometry")
            },
        );
        assert_eq!(result, Err("invalid geometry"));
        assert!(cache.is_none());
        assert_eq!(next, 2);
        assert_eq!(
            *events.borrow(),
            [
                "acquire:1",
                "query:1",
                "drop:1",
                "acquire:2",
                "query:2",
                "drop:2"
            ]
        );
    }

    #[test]
    fn initial_acquisition_error_does_not_loop_or_query() {
        let mut cache: Option<Token> = None;
        let mut attempts = 0;
        let result = query_cached(
            &mut cache,
            || {
                attempts += 1;
                Err("no display token")
            },
            |_| panic!("query without a token"),
        );
        assert_eq!(result, Err::<u32, _>("no display token"));
        assert_eq!(attempts, 1);
        assert!(cache.is_none());
    }

    #[test]
    fn explicit_invalidation_drops_once_and_next_query_acquires_again() {
        let events = Events::default();
        let mut cache = Some(token(1, &events));
        drop(cache.take());
        drop(cache.take());
        assert_eq!(
            query_cached(&mut cache, || Ok(token(2, &events)), query),
            Ok(2)
        );
        drop(cache.take());
        assert_eq!(
            *events.borrow(),
            ["acquire:1", "drop:1", "acquire:2", "query:2", "drop:2"]
        );
    }
}
