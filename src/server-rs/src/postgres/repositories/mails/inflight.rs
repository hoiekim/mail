//! Single-flight coalescing for identical, currently-running work
//! (repositories/mails/inflight.ts).
//!
//! If a call arrives while an identical one is in flight, the second caller
//! awaits the same result instead of starting a duplicate load, so the
//! memory footprint is one load per distinct in-flight shape rather than one
//! per concurrent caller.
//!
//! This is not a cache. The entry is removed the instant the work settles,
//! whether it succeeded or failed, so later callers get a fresh load. The
//! only overlap window is "callers that arrived while the first was still
//! running", which is exactly the client-retry-storm shape.
//!
//! ```ignore
//! let mails: Arc<Mails> = single_flight(key, move || load_mails(query)).await;
//! ```

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::panic::resume_unwind;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use futures_util::future::{FutureExt, Shared};

type Settled = Result<Arc<dyn Any + Send + Sync>, Arc<Mutex<Option<Box<dyn Any + Send>>>>>;
type Pending = Shared<Pin<Box<dyn Future<Output = Settled> + Send>>>;

fn inflight() -> &'static Mutex<HashMap<String, Pending>> {
    static INFLIGHT: OnceLock<Mutex<HashMap<String, Pending>>> = OnceLock::new();
    INFLIGHT.get_or_init(Default::default)
}

/// Removes the key's entry when the work is over, however it ends.
struct Settle(String);

impl Drop for Settle {
    fn drop(&mut self) {
        if let Ok(mut pending) = inflight().lock() {
            pending.remove(&self.0);
        }
    }
}

/// Runs `work` unless work under the same `key` is already running, in which
/// case this caller waits for that run and receives a clone of its output.
///
/// The work starts at once on its own task and runs to completion whether or
/// not any caller is still waiting, so one cancelled caller cannot strand the
/// others, and a failed run never lingers: the entry is gone before any
/// caller sees the output. A failure travels in the output type; every
/// waiter of one run sees the same one.
pub fn single_flight<T, F, Fut>(key: &str, work: F) -> impl Future<Output = T> + Send + 'static
where
    T: Clone + Send + Sync + 'static,
    F: FnOnce() -> Fut,
    Fut: Future<Output = T> + Send + 'static,
{
    let pending = {
        let mut entries = inflight().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(key) {
            Some(pending) => pending.clone(),
            None => {
                let settle = Settle(key.to_string());
                let run = work();
                let task = tokio::spawn(async move {
                    let _settle = settle;
                    let output: Arc<dyn Any + Send + Sync> = Arc::new(run.await);
                    output
                });
                let pending: Pending = (Box::pin(async move {
                    match task.await {
                        Ok(output) => Ok(output),
                        Err(error) => Err(Arc::new(Mutex::new(error.try_into_panic().ok()))),
                    }
                }) as Pin<Box<dyn Future<Output = Settled> + Send>>)
                    .shared();
                entries.insert(key.to_string(), pending.clone());
                pending
            }
        }
    };
    async move {
        match pending.await {
            Ok(output) => match output.downcast::<T>() {
                Ok(output) => (*output).clone(),
                Err(_) => panic!("single_flight: one key was used for two result types"),
            },
            Err(panic) => {
                let payload = panic.lock().ok().and_then(|mut payload| payload.take());
                match payload {
                    Some(payload) => resume_unwind(payload),
                    None => panic!("single_flight: the coalesced work panicked or was cancelled"),
                }
            }
        }
    }
}

/// The number of in-flight entries, for tests.
pub fn inflight_size() -> usize {
    inflight().lock().map(|entries| entries.len()).unwrap_or(0)
}

/// Clears all in-flight state, for tests. Never called by production code.
pub fn inflight_reset() {
    if let Ok(mut entries) = inflight().lock() {
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::oneshot;

    use super::*;

    /// The in-flight map is process-wide, so these tests take turns.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        let guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        inflight_reset();
        guard
    }

    type Outcome = Result<Arc<String>, String>;

    // inflight.test.ts — "singleFlight"

    #[tokio::test]
    async fn coalesces_two_callers_with_the_same_key_into_one_work_invocation() {
        let _serial = serial();
        let invocations = Arc::new(AtomicUsize::new(0));
        let (resolve, gate) = oneshot::channel::<Arc<String>>();
        let gate = gate.shared();
        let work = || {
            let invocations = invocations.clone();
            let gate = gate.clone();
            move || {
                invocations.fetch_add(1, Ordering::SeqCst);
                async move { gate.await.unwrap() }
            }
        };

        let first = single_flight("k", work());
        let second = single_flight("k", work());
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert_eq!(inflight_size(), 1);

        resolve.send(Arc::new("body".to_string())).unwrap();
        let (first, second) = (first.await, second.await);
        assert_eq!(*first, "body");
        assert_eq!(*second, "body");
        // Both callers hold the very same value: proof of coalescing.
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn does_not_coalesce_across_different_keys() {
        let _serial = serial();
        let invocations = Arc::new(AtomicUsize::new(0));
        let (resolve_a, gate_a) = oneshot::channel::<Arc<String>>();
        let (resolve_b, gate_b) = oneshot::channel::<Arc<String>>();
        let work = |gate: oneshot::Receiver<Arc<String>>| {
            let invocations = invocations.clone();
            move || {
                invocations.fetch_add(1, Ordering::SeqCst);
                async move { gate.await.unwrap() }
            }
        };

        let a = single_flight("a", work(gate_a));
        let b = single_flight("b", work(gate_b));
        assert_eq!(invocations.load(Ordering::SeqCst), 2);
        assert_eq!(inflight_size(), 2);

        resolve_a.send(Arc::new("A".to_string())).unwrap();
        resolve_b.send(Arc::new("B".to_string())).unwrap();
        let (a, b) = (a.await, b.await);
        assert!(!Arc::ptr_eq(&a, &b));
        assert_eq!(*a, "A");
        assert_eq!(*b, "B");
    }

    #[tokio::test]
    async fn deletes_the_entry_on_success_so_subsequent_callers_start_fresh() {
        let _serial = serial();
        let invocations = Arc::new(AtomicUsize::new(0));
        let run = || {
            let invocations = invocations.clone();
            single_flight("k", move || async move { invocations.fetch_add(1, Ordering::SeqCst) + 1 })
        };

        assert_eq!(run().await, 1);
        // A later caller must not ride the completed run: this is not a cache.
        assert_eq!(inflight_size(), 0);
        assert_eq!(run().await, 2);
    }

    #[tokio::test]
    async fn deletes_the_entry_on_failure_so_a_failed_load_does_not_stick() {
        let _serial = serial();
        let invocations = Arc::new(AtomicUsize::new(0));
        let run = || {
            let invocations = invocations.clone();
            single_flight("k", move || async move {
                let attempt = invocations.fetch_add(1, Ordering::SeqCst) + 1;
                Outcome::Err(format!("boom {attempt}"))
            })
        };

        assert_eq!(run().await, Err("boom 1".to_string()));
        // The second call re-runs the work instead of repeating the error.
        assert_eq!(inflight_size(), 0);
        assert_eq!(run().await, Err("boom 2".to_string()));
    }

    #[tokio::test]
    async fn callers_waiting_on_a_failing_in_flight_all_see_the_same_rejection() {
        let _serial = serial();
        let invocations = Arc::new(AtomicUsize::new(0));
        let (reject, gate) = oneshot::channel::<String>();
        let gate = gate.shared();
        let work = || {
            let invocations = invocations.clone();
            let gate = gate.clone();
            move || {
                invocations.fetch_add(1, Ordering::SeqCst);
                async move { Outcome::Err(gate.await.unwrap()) }
            }
        };

        let first = single_flight("k", work());
        let second = single_flight("k", work());
        assert_eq!(invocations.load(Ordering::SeqCst), 1);

        reject.send("shared".to_string()).unwrap();
        assert_eq!(first.await, Err("shared".to_string()));
        assert_eq!(second.await, Err("shared".to_string()));
        assert_eq!(inflight_size(), 0);
    }

    // Beyond inflight.test.ts: what a promise gives for free and a future
    // does not.

    #[tokio::test]
    async fn the_work_finishes_and_the_entry_clears_when_every_caller_gives_up() {
        let _serial = serial();
        let (resolve, gate) = oneshot::channel::<u8>();
        let (done, finished) = oneshot::channel::<()>();
        let waiting = single_flight("k", move || async move {
            let value = gate.await.unwrap();
            let _ = done.send(());
            value
        });
        assert_eq!(inflight_size(), 1);
        drop(waiting);

        resolve.send(7).unwrap();
        finished.await.unwrap();
        tokio::task::yield_now().await;
        for _ in 0..100 {
            if inflight_size() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert_eq!(inflight_size(), 0);
    }

    #[tokio::test]
    async fn a_panic_in_the_work_reaches_every_waiter_and_clears_the_entry() {
        let _serial = serial();
        async fn explode() -> u8 {
            panic!("exploded")
        }
        let first = tokio::spawn(single_flight("k", explode));
        let message = first.await.unwrap_err().into_panic();
        assert_eq!(message.downcast_ref::<&str>(), Some(&"exploded"));
        assert_eq!(inflight_size(), 0);
    }
}
