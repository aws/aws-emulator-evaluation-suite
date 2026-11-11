"""The runner reaches only a loopback emulator, signs only with an emulator's keys, and keeps
no ambient AWS identity."""

import argparse
import os
import subprocess
import sys
import textwrap

import pytest

from fidelity_tests_runner import credentials
from fidelity_tests_runner.cli import InputError, add_target_arguments, context_factory, main
from fidelity_tests_runner.context import FIXED_CREDS, Context
from fidelity_tests_runner.target import EndpointRefused, RealAwsRefused, require_loopback

NOT_LOOPBACK = (
    "https://52.94.236.248",
    "http://169.254.169.254",
    "http://10.0.0.5:4566",
    "https://emulator.example.com:4566",
)
LOOPBACK = ("http://127.0.0.1:4566", "https://localhost:4566", "http://[::1]:4566")


def _args(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    add_target_arguments(parser)
    return parser.parse_args(list(argv))


@pytest.fixture
def _restore_aws_env(monkeypatch):
    """Lets ``context_factory`` rewrite the AWS environment without leaking into other tests."""
    for name in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_EC2_METADATA_DISABLED"):
        monkeypatch.setenv(name, "unset-by-test")


@pytest.mark.parametrize("endpoint", NOT_LOOPBACK)
def test_a_non_loopback_endpoint_is_refused(endpoint):
    with pytest.raises(EndpointRefused, match="loopback"):
        require_loopback(endpoint)
    with pytest.raises(EndpointRefused, match="loopback"):
        Context(endpoint, creds=FIXED_CREDS)


@pytest.mark.parametrize(
    "endpoint", ["https://sts.us-west-2.amazonaws.com", "https://abc.lambda-url.us-west-2.on.aws"]
)
def test_an_aws_endpoint_is_refused_as_real_aws(endpoint):
    with pytest.raises(RealAwsRefused, match="emulator only"):
        require_loopback(endpoint)


@pytest.mark.parametrize("endpoint", NOT_LOOPBACK)
def test_the_cli_refuses_a_non_loopback_endpoint_before_reading_keys(endpoint, _restore_aws_env):
    with pytest.raises(InputError, match="loopback"):
        context_factory(_args("--endpoint", endpoint, "--auth", "off"))


@pytest.mark.parametrize("endpoint", LOOPBACK)
def test_a_loopback_endpoint_is_accepted(endpoint):
    require_loopback(endpoint)
    assert Context(endpoint, creds=FIXED_CREDS).client("sqs")


def test_an_aws_issued_key_file_is_refused(tmp_path):
    path = tmp_path / "keys"
    path.write_text("aws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=x\n")
    with pytest.raises(ValueError, match="AWS-issued"):
        credentials.read_key_file(path)


def test_a_key_file_with_a_session_token_is_refused(tmp_path):
    path = tmp_path / "keys"
    path.write_text("aws_access_key_id=EMULATORKEY\naws_secret_access_key=x\naws_session_token=t\n")
    with pytest.raises(ValueError, match="AWS-issued"):
        credentials.read_key_file(path)


def test_a_multi_profile_file_is_refused(tmp_path):
    path = tmp_path / "keys"
    path.write_text(
        "[default]\naws_access_key_id=EMULATORKEY\naws_secret_access_key=x\n"
        "[prod]\naws_access_key_id=EMULATORKEY2\naws_secret_access_key=y\n"
    )
    with pytest.raises(ValueError, match="profiles"):
        credentials.read_key_file(path)


def test_an_emulator_default_key_file_is_accepted(tmp_path):
    path = tmp_path / "keys"
    path.write_text("[default]\naws_access_key_id=EMULATORKEY\naws_secret_access_key=s3cret\n")
    creds = credentials.read_key_file(path)
    assert (creds.access_key, creds.secret_key) == ("EMULATORKEY", "s3cret")


def test_ambient_aws_credentials_are_cleared_for_the_test(monkeypatch, tmp_path):
    ambient = {
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "x",
        "AWS_SESSION_TOKEN": "t",
        "AWS_PROFILE": "prod",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://169.254.170.2/creds",
        "AWS_BEARER_TOKEN_BEDROCK": "b",
        "HTTPS_PROXY": "http://proxy.example:3128",
    }
    for name, value in ambient.items():
        monkeypatch.setenv(name, value)
    check = tmp_path / "svc" / "check_env.py"
    check.parent.mkdir()
    check.write_text(
        textwrap.dedent(
            f"""
            import os

            def run(ctx):
                assert not set({sorted(ambient)!r}) & set(os.environ)
                assert os.environ["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull
                assert os.environ["AWS_CONFIG_FILE"] == os.devnull
                assert os.environ["AWS_EC2_METADATA_DISABLED"] == "true"
            """
        )
    )
    assert main(["run", str(check), "--endpoint", "http://127.0.0.1:9", "--auth", "off"]) == 0
    assert os.environ["AWS_PROFILE"] == "prod"  # restored after the run


def test_python_dash_o_is_refused(tmp_path):
    check = tmp_path / "check_example.py"
    check.write_text(
        textwrap.dedent(
            """
            CHECK = "example"
            GROUP = "grp"

            def run(ctx):
                assert False
            """
        )
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONOPTIMIZE"}
    cmd = [sys.executable, "-O", "-m", "fidelity_tests_runner", "run", str(check)]
    cmd += ["--endpoint", "http://127.0.0.1:9", "--auth", "off"]
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
    assert done.returncode == 2, done.stdout + done.stderr
    assert "assertions stripped" in done.stderr


def _key_file(
    home, port, text="[default]\naws_access_key_id = test\naws_secret_access_key = test\n"
):
    folder = home / ".aws" / "emulator" / str(port)
    folder.mkdir(parents=True, mode=0o700)
    path = folder / credentials.KEY_FILE
    path.write_text(text)
    path.chmod(0o600)
    return path


@pytest.fixture
def key_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setattr(credentials, "key_home", home)
    return home


def test_a_key_file_is_read_from_the_emulators_home(key_home):
    _key_file(key_home, 4566)
    assert credentials.minted_credentials("http://127.0.0.1:4566").access_key == "test"


def test_a_key_file_that_links_outside_the_home_is_not_read(key_home, tmp_path):
    secret = tmp_path / "host-secret"
    secret.write_text("[default]\naws_access_key_id = stolen\naws_secret_access_key = stolen\n")
    folder = key_home / ".aws" / "emulator" / "4566"
    folder.mkdir(parents=True, mode=0o700)
    (folder / credentials.KEY_FILE).symlink_to(secret)
    assert credentials.minted_credentials("http://127.0.0.1:4566") is None


def test_a_key_file_another_user_could_have_written_is_not_read(key_home):
    path = _key_file(key_home, 4566)
    path.parent.chmod(0o770)
    assert credentials.minted_credentials("http://127.0.0.1:4566") is None
    path.parent.chmod(0o700)
    path.chmod(0o666)
    assert credentials.minted_credentials("http://127.0.0.1:4566") is None


def test_a_key_file_swapped_for_a_link_after_the_lookup_is_refused(key_home, tmp_path):
    path = _key_file(key_home, 4566)
    found = credentials.credentials_file(4566, key_home)
    path.unlink()
    path.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(PermissionError, match="is a link"):
        credentials.read_published(found)


def test_a_key_file_that_vanishes_during_the_lookup_sorts_first(key_home):
    assert credentials._mtime(key_home / "gone") == float("-inf")


def test_a_refused_host_is_not_swallowed_by_a_tests_except_exception():
    """A refusal is a ``BaseException``: a test's broad handler cannot turn it into a pass."""
    from fidelity_tests_runner import run_check
    from fidelity_tests_runner.target import NonLocalHostRefused, require_local_host
    from fidelity_tests_runner.verdicts import FAULT_HOST

    endpoint = "http://127.0.0.1:9"

    def check(ctx):
        try:
            require_local_host("emulator.example.com", endpoint)
        except Exception:  # what a test's retry loop does
            pass

    assert not issubclass(NonLocalHostRefused, Exception)
    result = run_check(lambda: Context(endpoint, creds=FIXED_CREDS), "c", "g", check, timeout_s=5)
    assert result.verdict == "error" and result.runner_fault == FAULT_HOST
