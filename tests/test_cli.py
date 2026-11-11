"""``fidelity-tests-runner run``, the test footer and ``requirements``: auth, exit codes, report."""

import json
import subprocess
import sys
import textwrap
import time

import pytest

from fidelity_tests_runner import EXIT_CLEANUP, EXIT_ERROR, EXIT_FAILED, EXIT_PASS, credentials
from fidelity_tests_runner.cli import main

#: Nothing listens here; the checks below never call the emulator unless they say so.
ENDPOINT = "http://127.0.0.1:9"
PORT = 9


@pytest.fixture(autouse=True)
def _fresh_key_home(monkeypatch, tmp_path):
    monkeypatch.setattr(credentials, "key_home", None)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def _check(tmp_path, body: str, name: str = "check_example.py"):
    suite = tmp_path / "svc"
    suite.mkdir(exist_ok=True)
    path = suite / name
    head = 'from behavioral_harness import tags\n\nCHECK = "example"\nGROUP = "grp"\n\n\n'
    run = '@tags("axis:happy-path")\ndef run(ctx):\n'
    run += textwrap.indent(textwrap.dedent(body).strip() + "\n", "    ")
    foot = (
        '\n\nif __name__ == "__main__":\n'
        "    from fidelity_tests_runner import main\n\n"
        "    main(run)\n"
    )
    path.write_text(head + run + foot)
    return path


def _emulator_home(tmp_path, key="AKEMULATOR", secret="s3cret"):
    home = tmp_path / "emu-home"
    keys = home / ".aws" / "emulator" / str(PORT)
    keys.mkdir(parents=True)
    (keys / "emulator_credentials").write_text(
        f"aws_access_key_id={key}\naws_secret_access_key={secret}\n"
    )
    return home


def _run(*argv):
    try:
        return main(["run", *map(str, argv)])
    except SystemExit as exc:
        return exc.code


def test_auth_on_signs_with_the_emulators_minted_keys(tmp_path):
    check = _check(tmp_path, 'assert ctx._creds["aws_access_key_id"] == "AKEMULATOR"')
    home = _emulator_home(tmp_path)
    assert _run(check, "--endpoint", ENDPOINT, "--emulator-home", home) == EXIT_PASS


def test_auth_on_without_a_key_file_is_an_input_error(tmp_path, capsys):
    check = _check(tmp_path, "pass")
    assert _run(check, "--endpoint", ENDPOINT) == 2
    assert "no key file" in capsys.readouterr().err


def test_an_explicit_credentials_file_wins(tmp_path):
    check = _check(tmp_path, 'assert ctx._creds["aws_access_key_id"] == "AKFILE"')
    key_file = tmp_path / "keys"
    key_file.write_text("aws_access_key_id=AKFILE\naws_secret_access_key=x\n")
    assert _run(check, "--endpoint", ENDPOINT, "--credentials-file", key_file) == EXIT_PASS


def test_a_key_file_without_a_pair_is_an_input_error(tmp_path):
    check = _check(tmp_path, "pass")
    key_file = tmp_path / "keys"
    key_file.write_text("nothing=here\n")
    assert _run(check, "--endpoint", ENDPOINT, "--credentials-file", key_file) == 2


def test_auth_off_signs_with_the_fixed_keys(tmp_path):
    check = _check(tmp_path, 'assert ctx._creds["aws_access_key_id"] == "test"')
    assert _run(check, "--endpoint", ENDPOINT, "--auth", "off") == EXIT_PASS


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://sts.us-west-2.amazonaws.com",
        "https://sqs.cn-north-1.amazonaws.com.cn",
        "https://sqs.us-iso-east-1.c2s.ic.gov",
        "https://abc.lambda-url.us-west-2.on.aws",
        "https://d111111abcdef8.cloudfront.net",
    ],
)
def test_an_aws_endpoint_is_refused(tmp_path, capsys, endpoint):
    """Any partition's endpoints and the data planes AWS publishes."""
    check = _check(tmp_path, "pass")
    assert _run(check, "--endpoint", endpoint, "--auth", "off") == 2
    assert "is an AWS endpoint" in capsys.readouterr().err


def test_disabled_tls_verification_is_refused_off_loopback(tmp_path):
    check = _check(tmp_path, "pass")
    endpoint = "https://emulator.example:4566"
    assert _run(check, "--endpoint", endpoint, "--auth", "off", "--no-verify-ssl") == 2


@pytest.mark.parametrize(
    ("body", "code", "verdict"),
    [
        ("pass", EXIT_PASS, "passed"),
        ("assert 1 == 2, 'differs'", EXIT_FAILED, "failed"),
        ("raise RuntimeError('boom')", EXIT_ERROR, "error"),
    ],
)
def test_exit_code_and_report_follow_the_verdict(tmp_path, body, code, verdict):
    check = _check(tmp_path, body)
    report = tmp_path / "report.json"
    assert _run(check, "--endpoint", ENDPOINT, "--auth", "off", "--report", report) == code
    doc = json.loads(report.read_text())
    assert doc["schema"] == "fidelity-tests-runner/report/v1"
    assert doc["check"]["verdict"] == verdict
    assert doc["check"]["service"] == "svc"
    assert doc["check"]["check_id"] == "svc.example"
    assert ("site" in doc["check"]) == (verdict != "passed")


def test_a_teardown_failure_is_reported_and_never_changes_the_verdict(tmp_path):
    body = "def boom():\n    raise RuntimeError('left behind')\nctx.on_cleanup(boom)"
    check = _check(tmp_path, body)
    report = tmp_path / "report.json"
    assert _run(check, "--endpoint", ENDPOINT, "--auth", "off", "--report", report) == EXIT_PASS
    assert "left behind" in json.loads(report.read_text())["check"]["cleanup_detail"]


def test_strict_cleanup_exits_13_on_a_teardown_failure_and_keeps_the_verdict(tmp_path):
    body = "def boom():\n    raise RuntimeError('left behind')\nctx.on_cleanup(boom)"
    check = _check(tmp_path, body)
    report = tmp_path / "report.json"
    argv = (check, "--endpoint", ENDPOINT, "--auth", "off", "--report", report)
    assert _run(*argv, "--strict-cleanup") == EXIT_CLEANUP == 13
    entry = json.loads(report.read_text())["check"]
    assert entry["verdict"] == "passed" and entry["cleanup_failed"] is True


def test_a_file_that_fails_to_load_is_an_error(tmp_path):
    path = tmp_path / "check_broken.py"
    path.write_text("import not_a_module_anywhere\n")
    assert _run(path, "--endpoint", ENDPOINT, "--auth", "off") == EXIT_ERROR


def test_the_footer_runs_the_check_standalone(tmp_path):
    check = _check(tmp_path, 'assert ctx._creds["aws_access_key_id"] == "AKEMULATOR"')
    home = _emulator_home(tmp_path)
    cmd = [sys.executable, str(check), "--endpoint", ENDPOINT, "--emulator-home", str(home)]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert done.returncode == EXIT_PASS, done.stdout + done.stderr
    assert "PASS" in done.stdout


def test_the_footer_refuses_to_run_without_keys(tmp_path):
    check = _check(tmp_path, "pass")
    env = {"PATH": "", "HOME": str(tmp_path / "nowhere")}
    cmd = [sys.executable, str(check), "--endpoint", ENDPOINT]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
    assert done.returncode == 2
    assert "no key file" in done.stderr


@pytest.mark.parametrize("standalone", [True, False])
def test_a_timed_out_check_exits_at_its_budget(tmp_path, standalone):
    """Its pool worker cannot be stopped, and a normal exit would wait for it."""
    body = """
    import concurrent.futures, time
    concurrent.futures.ThreadPoolExecutor(1).submit(time.sleep, 20)
    time.sleep(20)
    """
    check = _check(tmp_path, body)
    target = [str(check)] if standalone else ["-m", "fidelity_tests_runner", "run", str(check)]
    cmd = [sys.executable, *target, "--endpoint", ENDPOINT, "--auth", "off", "--timeout", "1"]
    started = time.monotonic()
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert done.returncode == EXIT_FAILED, done.stdout + done.stderr
    assert "timed out" in done.stdout
    assert time.monotonic() - started < 15


def test_requirements_lists_tools_packages_and_notes(tmp_path, capsys):
    body = """
    import psycopg
    from fidelity_tests_runner import require_tools
    require_tools("terraform")
    open("deployments/app/main.tf")
    """
    check = _check(tmp_path, body)
    main(["requirements", "--json", str(check)])
    (report,) = json.loads(capsys.readouterr().out)
    assert report["tools"] == ["terraform"]
    assert report["python_packages"] == ["psycopg[binary]"]
    assert any("needs deployments/" in n for n in report["notes"])


@pytest.mark.parametrize("standalone", [True, False])
def test_a_retry_that_passes_exits_at_once_and_both_paths_agree(tmp_path, standalone):
    """The first attempt times out with a pool worker still sleeping; the retry passes."""
    marker = tmp_path / "attempted"
    body = f"""
    import concurrent.futures, pathlib, time
    marker = pathlib.Path({str(marker)!r})
    if not marker.exists():
        marker.write_text("1")
        concurrent.futures.ThreadPoolExecutor(1).submit(time.sleep, 20)
        time.sleep(20)
    """
    check = _check(tmp_path, body)
    target = [str(check)] if standalone else ["-m", "fidelity_tests_runner", "run", str(check)]
    report = tmp_path / "report.json"
    cmd = [sys.executable, *target, "--endpoint", ENDPOINT, "--auth", "off", "--timeout", "1"]
    cmd += ["--retry-timeout", "--report", str(report)]
    started = time.monotonic()
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert done.returncode == EXIT_PASS, done.stdout + done.stderr
    assert time.monotonic() - started < 15
    assert "PASS (retry after a timeout)" in done.stdout
    entry = json.loads(report.read_text())["check"]
    assert entry["retried_after_timeout"] is True and entry["verdict"] == "passed"


def test_report_to_stdout_is_pure_json_and_the_console_line_goes_to_stderr(tmp_path, capsys):
    check = _check(tmp_path, "pass")
    assert _run(check, "--endpoint", ENDPOINT, "--auth", "off", "--report", "-") == EXIT_PASS
    out, err = capsys.readouterr()
    assert json.loads(out)["check"]["verdict"] == "passed"
    assert "PASS" in err


@pytest.mark.parametrize("region", ["us west 2", "", "us-west-2;rm", "US-WEST-2"])
def test_a_malformed_region_is_an_input_error(tmp_path, region):
    check = _check(tmp_path, "pass")
    assert _run(check, "--endpoint", ENDPOINT, "--auth", "off", "--region", region) == 2


@pytest.mark.parametrize("region", ["us-west-2", "eu-central-1", "us-gov-west-1", "cn-north-1"])
def test_a_region_of_any_partition_is_accepted(tmp_path, region):
    check = _check(tmp_path, "pass")
    assert _run(check, "--endpoint", ENDPOINT, "--auth", "off", "--region", region) == EXIT_PASS


def test_a_url_no_customer_can_use_fails_the_test_as_a_published_url(tmp_path):
    check = _check(tmp_path, 'ctx.endpoint_url("https://203.0.113.5:8443/x")')
    report = tmp_path / "report.json"
    assert _run(check, "--endpoint", ENDPOINT, "--auth", "off", "--report", report) == EXIT_FAILED
    entry = json.loads(report.read_text())["check"]
    assert entry["kind"] == "published_url" and entry["verdict"] == "failed"
    assert entry["published_url_violations"] == [
        {"field": "endpoint_url", "reason": "host_not_own", "value_class": "url", "host": "<ip>"}
    ]


def test_an_own_host_option_makes_a_host_an_own_host(tmp_path):
    check = _check(tmp_path, 'ctx.endpoint_url("http://bkt.s3.localhost:4566/x")')
    argv = ("--endpoint", ENDPOINT, "--auth", "off")
    assert _run(check, *argv) == EXIT_FAILED
    assert _run(check, *argv, "--own-host", "*.localhost") == EXIT_PASS
