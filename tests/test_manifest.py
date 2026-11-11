"""``manifest.jsonl`` describes exactly the shipped fidelity tests, one row each.

A row has exactly the keys check_id, key, path, service, operations, labels, and deployments,
and its labels come only from the namespaces ``docs/TAXONOMY.md`` describes.
"""

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
KEYS = frozenset({"check_id", "key", "path", "service", "operations", "labels", "deployments"})
MANIFEST = ROOT / "manifest.jsonl"
LABELS = re.compile(
    r"plane:(control|data)|dp:(api|native|endpoint)"
    r"|axis:(rejection|happy-path|negative-delivery)|timing:real-time"
)
OPERATION = re.compile(r"[a-z0-9][a-z0-9-]*:[A-Z][A-Za-z0-9]*")

pytestmark = pytest.mark.skipif(not MANIFEST.is_file(), reason="no exported checks here")


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return [json.loads(line) for line in MANIFEST.read_text().splitlines() if line.strip()]


def test_one_row_per_check_file(rows):
    on_disk = sorted(p.relative_to(ROOT).as_posix() for p in ROOT.glob("behavioral/*/check_*.py"))
    assert sorted(r["path"] for r in rows) == on_disk


def test_keys_are_unique_and_name_the_directory_and_check(rows):
    keys = [r["key"] for r in rows]
    assert len(keys) == len(set(keys))
    for r in rows:
        service, _, name = r["key"].partition("/")
        assert service == Path(r["path"]).parent.name == r["service"] and name, r["key"]
        # The ID is stable: a test that was moved or renamed keeps the one it had.
        id_service, _, id_name = r["check_id"].partition(".")
        assert id_service and id_name, r["key"]
    ids = [r["check_id"] for r in rows]
    assert len(ids) == len(set(ids))


def test_every_row_names_its_operations_with_their_service(rows):
    assert sum(bool(r["operations"]) for r in rows) > 0.99 * len(rows)
    for r in rows:
        bad = [op for op in r["operations"] if not OPERATION.fullmatch(op)]
        assert not bad, (r["key"], bad)


def test_every_row_has_exactly_the_keys_and_taxonomy_labels(rows):
    for r in rows:
        assert r.keys() == KEYS, (r["key"], sorted(r.keys() ^ KEYS))
        bad = [t for t in r["labels"] if not LABELS.fullmatch(t)]
        assert not bad, (r["key"], bad)


def test_the_taxonomy_describes_every_label(rows):
    taxonomy = (ROOT / "docs" / "TAXONOMY.md").read_text()
    for label in {t for r in rows for t in r["labels"]}:
        assert f"`{label}`" in taxonomy, label


def test_the_deployments_a_row_names_are_shipped(rows):
    for r in rows:
        for entry in r["deployments"]:
            assert (ROOT / entry).exists(), (r["key"], entry)


def test_a_moved_test_is_reported_under_its_manifest_id(tmp_path):
    from fidelity_tests_runner.context import FIXED_CREDS, Context
    from fidelity_tests_runner.run import _manifest_ids, check_entry, manifest_check_id, run_file

    test = tmp_path / "behavioral" / "a__b" / "check_x.py"
    test.parent.mkdir(parents=True)
    test.write_text('CHECK = "x"\n\ndef run(ctx):\n    pass\n')
    row = {"check_id": "a__b__c.x", "path": "behavioral/a__b/check_x.py"}
    (tmp_path / "manifest.jsonl").write_text(json.dumps(row) + "\n")
    _manifest_ids.cache_clear()
    assert manifest_check_id(test) == "a__b__c.x"
    result, report = run_file(
        test,
        lambda: Context("http://127.0.0.1:9", creds=dict(FIXED_CREDS)),
        endpoint="http://127.0.0.1:9",
        verify_ssl=False,
    )
    assert report["check"]["check_id"] == "a__b__c.x"
    assert report["check"]["service"] == "a__b"
    result.check_id = ""
    assert check_entry(result)["check_id"] == "a__b.x"


def test_every_shipped_test_is_reported_under_its_manifest_id(rows):
    from fidelity_tests_runner.run import manifest_check_id

    for r in rows:
        assert manifest_check_id(ROOT / r["path"]) == r["check_id"], r["key"]
