from engine.results import store


def test_rerun_drops_previous_incident_files(tmp_path):
    inc = lambda i: {"incident_id": i, "risk": 0.5, "verdict": "review"}
    store.write(str(tmp_path), {}, [], [inc(i) for i in range(1, 6)], {})
    store.write(str(tmp_path), {}, [], [inc(1)], {})
    _, full, _ = store.load(str(tmp_path))
    assert list(full) == [1]
