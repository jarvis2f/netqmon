use super::*;
use std::sync::mpsc;

struct PausedGeo {
    entered: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl GeoProvider for PausedGeo {
    fn lookup(&self, _: IpAddr) -> Result<Option<netqmon_geo::GeoRecord>, netqmon_geo::GeoError> {
        self.entered.send(()).unwrap();
        self.resume
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        Ok(None)
    }
    fn is_enabled(&self) -> bool {
        true
    }
}

#[test]
fn slow_classification_does_not_hold_the_state_mutex() {
    let state = test_state();
    let enrolled = state
        .enroll(&EnrollRequest {
            enrollment_token: ENROLLMENT_TOKEN.into(),
            agent_version: "test".into(),
            protocol_version: PROTOCOL_VERSION,
            boot_id: "boot-1".into(),
            gateway_name: "router".into(),
        })
        .unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    state.lock().geo_provider = Arc::new(PausedGeo {
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
    });
    let mut input = sample_batch(&enrolled.gateway_id, 1);
    input.flows[0].ip_version = 4;
    input.flows[0].protocol = 6;
    input.flows[0].client_ip = vec![192, 0, 2, 10];
    input.flows[0].remote_ip = vec![198, 51, 100, 1];
    input.flows[0].remote_port = 443;
    let worker_state = state.clone();
    let worker = std::thread::spawn(move || worker_state.accept_batch(&input));
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let accessible = state.inner.try_lock().is_ok();
    let serialized = state.processing.try_lock().is_err();
    resume_tx.send(()).unwrap();
    assert!(worker.join().unwrap().is_ok());
    assert!(
        accessible,
        "classification must not hold the query/state mutex"
    );
    assert!(serialized, "writer cache ownership must remain serialized");
}

#[test]
fn file_backed_queries_do_not_hold_the_writer_state_mutex() {
    let dir = tempdir().unwrap();
    let state = CollectorState::open(ENROLLMENT_TOKEN, &dir.path().join("reader.db")).unwrap();
    let query = state.query();
    let readable: i64 = query
        .storage
        .connection()
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .unwrap();
    assert_eq!(readable, 0);
    assert!(state.inner.try_lock().is_ok());
    state
        .lock()
        .storage
        .save_gateway("gateway-test", "router", "test", &[7; 32], unix_time_ms())
        .unwrap();
}

#[test]
fn query_entry_does_not_wait_for_the_ingestion_mutex() {
    let dir = tempdir().unwrap();
    let state = CollectorState::open(ENROLLMENT_TOKEN, &dir.path().join("entry.db")).unwrap();
    let guard = state.lock();
    let worker_state = state.clone();
    let (sender, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let query = worker_state.query();
        let count: i64 = query
            .storage
            .connection()
            .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
            .unwrap();
        sender.send(count).unwrap();
    });
    let result = receiver.recv_timeout(Duration::from_secs(2));
    drop(guard);
    worker.join().unwrap();
    assert_eq!(result.unwrap(), 0);
}
