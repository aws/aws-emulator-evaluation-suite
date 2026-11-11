"""``fidelity-tests-runner summarize`` scores report files with ``verdicts.score``."""

import json

from fidelity_tests_runner import verdicts
from fidelity_tests_runner.cli import main, summarize
from fidelity_tests_runner.harness import CheckResult
from fidelity_tests_runner.run import REPORT_SCHEMA, check_entry


def _result(name, service="sqs", **kw) -> CheckResult:
    base = {"passed": False, "detail": None, "duration_ms": 1.0, "verdict": "passed"}
    return CheckResult(name=name, group="g", service=service, **(base | kw))


def _write(tmp_path, results):
    for r in results:
        report = {"schema": REPORT_SCHEMA, "endpoint": "http://127.0.0.1:1"}
        report["check"] = check_entry(r)
        (tmp_path / f"{r.service}-{r.name}.json").write_text(json.dumps(report))


RESULTS = [
    _result("ok", passed=True),
    _result("wrong", verdict="failed"),
    _result("slow", verdict="failed", timed_out=True),
    _result("leak", service="s3", passed=True, cleanup_failed=True),
    _result("nokubectl", service="eks", verdict="error", tool_missing=("kubectl",)),
    _result("guarded", service="s3", verdict="error", runner_fault="setup"),
]


def test_an_entry_carries_only_the_public_fields():
    allowed = {
        "check_id",
        "service",
        "verdict",
        "kind",
        "duration_ms",
        "detail",
        "budget_s",
        "site",
        "tool_missing",
        "retried_after_timeout",
        "published_url_violations",
        "cleanup_failed",
        "cleanup_ms",
        "cleanup_detail",
    }
    for r in RESULTS:
        entry = check_entry(r)
        assert entry.keys() <= allowed, sorted(entry.keys() - allowed)
        assert entry["kind"] == verdicts.classify(r)


def test_the_summary_is_the_shared_score(tmp_path):
    _write(tmp_path, RESULTS)
    summary, problems = summarize([str(tmp_path)])
    expected = verdicts.score(RESULTS)
    assert not problems
    assert {k: summary[k] for k in expected} == expected
    assert (summary["n"], summary["passed"], summary["n_total"]) == (4, 2, 6)
    assert summary["failed_by_kind"]["timeout"] == 1
    assert summary["excluded_by_kind"]["tool_missing"] == 1
    assert summary["excluded_by_kind"]["runner_fault"] == 1
    assert summary["n_cleanup_failed"] == 1
    assert summary["by_service"]["s3"]["n"] == 1


def test_a_file_that_is_not_a_report_is_named_and_left_out(tmp_path):
    _write(tmp_path, RESULTS[:1])
    (tmp_path / "other.json").write_text('{"schema": "something-else"}')
    (tmp_path / "broken.json").write_text("{")
    summary, problems = summarize([str(tmp_path)])
    assert summary["n_total"] == 1 and len(problems) == 2


def test_the_command_prints_the_score_and_exits_1_on_nothing(tmp_path, capsys):
    _write(tmp_path, RESULTS)
    assert main(["summarize", str(tmp_path), "--by-service"]) == 0
    out = capsys.readouterr().out
    assert "n=4 passed=2 pass_rate=0.5000" in out and "  s3: 1/1" in out
    assert main(["summarize", "--json", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["n"] == 4
    empty = tmp_path / "empty"
    empty.mkdir()
    assert main(["summarize", str(empty)]) == 1
