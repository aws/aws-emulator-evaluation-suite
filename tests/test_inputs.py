"""What the emulator or the file system hands the runner is checked before it is used: API
Gateway tokens, report paths, report files, key files, the manifest and console output."""

import json
from pathlib import Path

import pytest

from fidelity_tests_runner import cli
from fidelity_tests_runner.context import FIXED_CREDS, Context
from fidelity_tests_runner.credentials import read_key_file
from fidelity_tests_runner.harness import VERDICT_FAILED, CheckResult
from fidelity_tests_runner.published import PublishedUrlRejected
from fidelity_tests_runner.run import REPORT_SCHEMA, check_entry

ENDPOINT = "http://127.0.0.1:4566"


@pytest.mark.parametrize(
    ("api_id", "stage"),
    [
        ("evil.example#", "prod"),
        ("x@evil.example/", "prod"),
        ("abc123", "../../admin"),
        ("abc123", "prod?x=1"),
        ("abc123", "prod#frag"),
        ("", "prod"),
        ("abc123", "a" * 129),
    ],
)
def test_an_api_id_or_stage_that_is_not_a_bare_token_is_refused(api_id, stage):
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    with pytest.raises(ValueError, match="not an API Gateway id or stage name"):
        ctx.api_url(api_id, stage)


def test_a_host_position_template_keeps_the_host_an_emulator_host(monkeypatch):
    template = "http://{api_id}.execute-api.localhost:{port}/{stage}"
    ctx = Context(ENDPOINT, creds=FIXED_CREDS, execute_api_url=template)
    assert ctx.api_url("abc123", "prod") == "http://abc123.execute-api.localhost:4566/prod"
    assert ctx.api_url("abc123", "$default") == "http://abc123.execute-api.localhost:4566"
    assert ctx.api_url("abc123", "v_1", websocket=True) == (
        "ws://abc123.execute-api.localhost:4566/v_1"
    )


def test_console_output_never_carries_a_raw_terminal_control():
    text = cli._printable("ok\x1b]0;title\x07\x1b[2K\r\nnext\tline\x9b")
    assert "\x1b" not in text and "\x07" not in text and "\r" not in text and "\x9b" not in text
    assert "\nnext\tline" in text and "\\x1b" in text


def _report(tmp_path: Path, name: str, check) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"schema": REPORT_SCHEMA, "check": check}))
    return path


def test_a_report_whose_check_is_malformed_is_a_problem_not_a_crash(tmp_path):
    good = CheckResult(
        name="c", group="g", passed=False, detail="x", duration_ms=1.0, verdict=VERDICT_FAILED
    )
    _report(tmp_path, "good.json", check_entry(good))
    _report(tmp_path, "nocheck.json", None)
    (tmp_path / "missing.json").write_text(json.dumps({"schema": REPORT_SCHEMA}))
    summary, problems = cli.summarize([str(tmp_path)])
    assert summary["n_total"] == 1
    assert sorted(Path(p.split(":")[0]).name for p in problems) == ["missing.json", "nocheck.json"]


def test_a_report_is_written_owner_only(tmp_path):
    with cli.open_report(tmp_path / "r.json") as out:
        out.write("{}")
    assert (tmp_path / "r.json").stat().st_mode & 0o777 == 0o600


def test_a_report_path_that_is_a_link_is_refused_and_its_target_untouched(tmp_path):
    target = tmp_path / "target"
    target.write_text("keep")
    (tmp_path / "r.json").symlink_to(target)
    with pytest.raises(cli.InputError):
        cli.open_report(tmp_path / "r.json")
    assert target.read_text() == "keep"


def test_an_existing_report_is_emptied_and_made_owner_only(tmp_path):
    path = tmp_path / "r.json"
    path.write_text("a much longer previous report")
    path.chmod(0o644)
    with cli.open_report(path) as out:
        out.write("{}")
    assert path.read_text() == "{}" and path.stat().st_mode & 0o777 == 0o600


def test_a_key_file_naming_a_key_twice_is_refused(tmp_path):
    path = tmp_path / "emulator_credentials"
    path.write_text("aws_access_key_id=EMU1\naws_secret_access_key=s\naws_access_key_id=EMU2\n")
    path.chmod(0o600)
    with pytest.raises(ValueError, match="names a key twice"):
        read_key_file(path)


def test_a_teardown_failure_detail_reduces_paths_as_a_check_failure_does():
    from fidelity_tests_runner.run import _run_cleanups

    class Ctx:
        def run_cleanups(self):
            raise RuntimeError('File "/home/someone/suite/behavioral/sqs/check_x.py", line 3')

    _, problem, failed = _run_cleanups(Ctx(), "c", 5.0)
    assert failed and "/home/someone" not in problem and 'File "check_x.py"' in problem


def test_the_invoke_url_template_is_read_from_the_environment(monkeypatch):
    monkeypatch.setenv(
        "FIDELITY_TESTS_EXECUTE_API_URL_TEMPLATE",
        "http://{api_id}.execute-api.localhost:{port}/{stage}",
    )
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    assert ctx.api_url("abc123", "prod") == "http://abc123.execute-api.localhost:4566/prod"


@pytest.mark.parametrize(
    "published",
    ["http://localhost:4566/x", "http://127.0.0.1:4599/x", "http://[::1]:4566/x"],
)
def test_a_url_on_an_own_host_is_handed_to_the_test_as_published(published):
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    assert ctx.endpoint_route(published) == (published, {})


def test_a_documented_own_host_is_an_own_host():
    ctx = Context(ENDPOINT, creds=FIXED_CREDS, own_hosts=["*.localhost"])
    assert ctx.endpoint_url("http://bkt.s3.localhost:4566/x") == "http://bkt.s3.localhost:4566/x"


@pytest.mark.parametrize(
    ("published", "reason"),
    [
        ("https://bkt.s3.us-west-2.amazonaws.com/key", "host_not_own"),
        ("http://bkt.s3.localhost:4566/x", "host_not_own"),
        ("http://lb.elb.10.0.0.5:8080/", "host_unresolvable"),
        ("http://172.17.0.2:9200/", "host_not_own"),
        ("http://203.0.113.5:8080/x", "host_not_own"),
        ("https://example.com/x", "host_not_own"),
    ],
)
def test_a_url_no_customer_of_the_emulator_can_use_fails_the_test(published, reason):
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    with pytest.raises(PublishedUrlRejected) as raised:
        ctx.endpoint_url(published)
    assert raised.value.reason == reason
    assert isinstance(raised.value, AssertionError)
    with pytest.raises(PublishedUrlRejected):
        ctx.client("sqs", endpoint_url=published)
    assert {v["reason"] for v in ctx.published_url_violations} == {reason}


def test_a_database_host_is_used_as_published_when_it_is_an_own_host():
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    assert ctx.endpoint_host("localhost:6379", 1) == ("localhost", 6379)
    assert ctx.endpoint_host("127.0.0.1", 5432) == ("127.0.0.1", 5432)
    for host in ("db.cluster-x.us-west-2.rds.amazonaws.com", "db.example.com", "10.0.0.7"):
        with pytest.raises(PublishedUrlRejected):
            ctx.endpoint_host(host, 5432)


def test_the_address_helpers_name_the_endpoint():
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    assert ctx.endpoint == ENDPOINT
    assert ctx.service_url("https://sqs.us-west-2.amazonaws.com") == ENDPOINT
    assert ctx.service_url("wss://data.iot.us-west-2.amazonaws.com:443") == "ws://127.0.0.1:4566"
    assert ctx.service_host("cassandra.us-west-2.amazonaws.com", 9142) == ("127.0.0.1", 9142)
    assert ctx.s3_object_url("https://b.s3.amazonaws.com/a b", "b", "a b/c~") == (
        f"{ENDPOINT}/b/a%20b/c~"
    )
    assert ctx.stage_url("http://127.0.0.1:4566/api", "prod") == f"{ENDPOINT}/api/prod"
    assert ctx.stage_url("ws://localhost:4566", "$default", management=True) == (
        "http://localhost:4566"
    )
    for bad in ("http://sqs.us-west-2.amazonaws.com", "https://example.com", "https://s3.aws/x"):
        with pytest.raises(ValueError):
            ctx.service_url(bad)


def test_no_template_means_the_emulator_offers_no_invoke_or_website_url():
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    with pytest.raises(AssertionError, match="no API Gateway invoke URL"):
        ctx.api_url("abc123", "prod")
    with pytest.raises(AssertionError, match="no S3 website endpoint"):
        ctx.s3_website_urls(["http://b.s3-website-us-west-2.amazonaws.com"], "b")
    ctx = Context(
        ENDPOINT, creds=FIXED_CREDS, s3_website_url="http://{bucket}.s3-website.localhost:{port}"
    )
    assert ctx.s3_website_urls([], "bkt") == ["http://bkt.s3-website.localhost:4566"]


@pytest.mark.parametrize(
    ("bucket", "region"),
    [("evil.example.com/#", None), ("bkt", "us-west-2/@evil.example.com"), ("UPPER", None)],
)
def test_an_s3_website_url_takes_only_a_bucket_name_and_a_region(bucket, region):
    """The URL is checked like any URL the context hands a test: no value can move its host."""
    ctx = Context(
        ENDPOINT,
        creds=FIXED_CREDS,
        s3_website_url="http://{bucket}.s3-website-{region}.localhost:{port}",
    )
    with pytest.raises(ValueError, match="not an S3 bucket name|not an AWS region"):
        ctx.s3_website_urls([], bucket, region=region)


def test_own_hosts_are_resolved_once_per_context(monkeypatch):
    from fidelity_tests_runner import published

    calls = []
    monkeypatch.setattr(published, "public_addresses", lambda name: calls.append(name) or ())
    Context(ENDPOINT, creds=FIXED_CREDS, own_hosts=["*.emu.test"])
    assert len(calls) == 1, calls


def test_the_manifest_is_read_only_from_the_suite_root(tmp_path):
    """A manifest in a shared ancestor never names a test's ID; only ``<root>/behavioral/...``'s."""
    from fidelity_tests_runner.run import _manifest_ids, manifest_check_id

    planted = {"check_id": "s3.planted", "path": "x/behavioral/svc/check_a.py"}
    (tmp_path / "manifest.jsonl").write_text(json.dumps(planted) + "\n")
    (tmp_path / "behavioral").mkdir()
    loose = tmp_path / "check_a.py"
    nested = tmp_path / "x" / "behavioral" / "svc" / "check_a.py"
    nested.parent.mkdir(parents=True)
    for test in (loose, nested):
        test.write_text("def run(ctx):\n    pass\n")
    _manifest_ids.cache_clear()
    assert manifest_check_id(loose) == ""
    assert manifest_check_id(nested) == ""
    own = {"check_id": "svc.own-id", "path": "behavioral/svc/check_a.py"}
    (tmp_path / "x" / "manifest.jsonl").write_text(json.dumps(own) + "\n")
    assert manifest_check_id(nested) == "svc.own-id"


def test_a_published_url_mismatch_grades_the_host_not_aws_labels():
    ctx = Context(ENDPOINT, creds=FIXED_CREDS)
    assert ctx.published_url_mismatch(f"{ENDPOINT}/2015-03-31/x", labels=("lambda-url",)) is None
    assert ctx.published_url_mismatch(f"{ENDPOINT}/a/b/c", path=r"/b") is None
    assert "no run of whole segments" in ctx.published_url_mismatch(f"{ENDPOINT}/a", path="/b")
    assert "not one of the emulator's own hosts" in ctx.published_url_mismatch(
        "https://abc.lambda-url.us-west-2.on.aws/"
    )
    assert [v["host"] for v in ctx.published_url_violations] == [
        "<ip>",
        "*.lambda-url.us-west-2.on.aws",
    ]


def test_an_invoke_url_template_on_a_remote_host_is_refused_up_front():
    with pytest.raises(ValueError, match="not a loopback or private address"):
        Context(ENDPOINT, creds=FIXED_CREDS, execute_api_url="http://203.0.113.5/{api_id}/{stage}")
    ctx = Context(
        ENDPOINT, creds=FIXED_CREDS, execute_api_url="{endpoint}/restapis/{api_id}/{stage}"
    )
    assert ctx.api_url("abc", "prod") == f"{ENDPOINT}/restapis/abc/prod"
