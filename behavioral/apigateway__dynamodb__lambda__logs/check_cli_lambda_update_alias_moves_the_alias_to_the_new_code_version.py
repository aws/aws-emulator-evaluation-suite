"""cli-lambda-update-alias-moves-the-alias-to-the-new-code-version."""
from __future__ import annotations

import io
import json
import os
import subprocess
import tempfile
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-lambda-update-alias-moves-the-alias-to-the-new-code-version"
GROUP = "cli-roundtrip"
SERVICES = ["lambda", "logs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Redeploying behind an alias with the CLI: after `update-function-code`, `publish-version` and
    `update-alias`, invoking the alias runs the new code and reports the new version, version 1 still
    runs the old code, and the new code's marker is logged only in a stream labelled version 2."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")
    tag = ctx.unique_name("t")
    fn = _create_lambda_function(ctx, _code(tag, "A", "event['n'] ** 2"))
    log_group = f"/aws/lambda/{fn}"

    v1 = _run_aws(ctx, "lambda", "publish-version", "--function-name", fn)
    assert v1.get("Version") == "1", f"publish-version returned Version {v1.get('Version')!r}, expected '1'"
    alias = _run_aws(ctx, "lambda", "create-alias", "--function-name", fn, "--name", "live",
                     "--function-version", "1")
    assert alias.get("FunctionVersion") == "1", f"create-alias returned {alias!r}"
    meta, payload = _cli_invoke(ctx, fn, 6, "live")
    assert (meta.get("ExecutedVersion"), payload) == ("1", {"code": "A", "out": 36}), (meta, payload)

    _cli_update_code(ctx, fn, _code(tag, "B", "event['n'] * 10 + 1"))
    _wait_updated(ctx, fn)
    v2 = _run_aws(ctx, "lambda", "publish-version", "--function-name", fn)
    assert v2.get("Version") == "2", f"publish-version returned Version {v2.get('Version')!r}, expected '2'"
    moved = _run_aws(ctx, "lambda", "update-alias", "--function-name", fn, "--name", "live",
                     "--function-version", "2")
    assert moved.get("FunctionVersion") == "2", f"update-alias returned {moved!r}"
    got = _run_aws(ctx, "lambda", "get-alias", "--function-name", fn, "--name", "live")
    assert got.get("FunctionVersion") == "2", f"get-alias after update-alias returned {got!r}"

    meta, payload = _cli_invoke(ctx, fn, 6, "live")
    assert (meta.get("ExecutedVersion"), payload) == ("2", {"code": "B", "out": 61}), (
        f"the alias after update-alias: expected version 2 running code B, got {meta!r} {payload!r}")
    meta, payload = _cli_invoke(ctx, fn, 6, "1")
    assert (meta.get("ExecutedVersion"), payload) == ("1", {"code": "A", "out": 36}), (
        f"version 1 after the redeploy: expected code A, got {meta!r} {payload!r}")

    streams = _wait_marker_streams(ctx, log_group, f"MARK-{tag}-B")
    labels = {_version_of_stream(s) for s in streams}
    assert labels == {"2"}, f"code B's marker is in streams labelled {sorted(labels)}, expected only version 2"


# ===== helpers =====


def _code(tag: str, letter: str, expr: str) -> str:
    """Handler source printing a run-unique marker and returning ``expr`` of the event's n."""
    return (
        "def handler(event, context):\n"
        f"    print('MARK-{tag}-{letter}')\n"
        f"    return {{'code': '{letter}', 'out': {expr}}}\n"
    )


def _run_shell(ctx, command, *, timeout_s=40):
    ctx.verify_account_safety()
    result = subprocess.run(command, env=ctx.subprocess_env(), capture_output=True, text=True,
                            timeout=timeout_s)
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=40):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s)
    return json.loads(proc.stdout) if proc.stdout.strip() else {}


def _cli_invoke(ctx, function_name: str, n: int, qualifier=None):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name
    try:
        args = ["lambda", "invoke", "--function-name", function_name,
                "--cli-binary-format", "raw-in-base64-out", "--payload", json.dumps({"n": n})]
        if qualifier:
            args += ["--qualifier", qualifier]
        meta = _run_aws(ctx, *args, out_path)
        with open(out_path) as fh:
            return meta, json.load(fh)
    finally:
        os.unlink(out_path)


def _cli_update_code(ctx, fn: str, code: str, *extra: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
        zf.write(_make_zip(code))
        zip_path = zf.name
    try:
        return _run_aws(ctx, "lambda", "update-function-code", "--function-name", fn,
                        "--zip-file", f"fileb://{zip_path}", *extra)
    finally:
        os.unlink(zip_path)


def _wait_updated(ctx, fn: str) -> dict:
    left = ctx.time_left()
    deadline = time.monotonic() + (40 if left is None else min(40, left))
    while True:
        cfg = _run_aws(ctx, "lambda", "get-function-configuration", "--function-name", fn)
        if cfg.get("LastUpdateStatus") == "Successful" and cfg.get("State") == "Active":
            return cfg
        if time.monotonic() >= deadline:
            raise AssertionError(f"{fn} never reached Active/Successful: {cfg!r}")
        time.sleep(2)


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code)
    return buf.getvalue()


def _teardown(undo, *not_found):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lmbrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_arn = f"arn:{role_arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn), "NoSuchEntity"))
    return role_arn


def _create_lambda_function(ctx, code: str) -> str:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    role_arn = _create_lambda_role(ctx)
    name = ctx.unique_name("sim2real-fn-")
    ctx.on_cleanup(_teardown(lambda: logs.delete_log_group(logGroupName=f"/aws/lambda/{name}"),
                             "ResourceNotFoundException"))
    deadline = time.monotonic() + 40
    while True:
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="lambda_function.handler",
                Code={"ZipFile": _make_zip(code)}, Timeout=10, Tags={"sim2real": CHECK},
            )
            break
        except ClientError as exc:
            # IAM propagation exposes no pollable condition; the bounded retry is the fix.
            if "cannot be assumed" not in str(exc) or time.monotonic() >= deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException"))
    _wait_updated(ctx, name)
    return name


def _marker_streams(ctx, log_group: str, marker: str) -> set:
    """Names of the log streams holding ``marker``; empty while the group does not exist."""
    logs = ctx.client("logs")
    try:
        events = logs.filter_log_events(logGroupName=log_group, filterPattern=f'"{marker}"')["events"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return set()
        raise
    return {e["logStreamName"] for e in events}


def _wait_marker_streams(ctx, log_group: str, marker: str, timeout_s=40) -> set:
    deadline = time.monotonic() + timeout_s
    while True:
        streams = _marker_streams(ctx, log_group, marker)
        if streams:
            return streams
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"marker {marker!r} not in {log_group} after {timeout_s}s: the last FilterLogEvents "
                f"found streams {sorted(streams)!r}")
        time.sleep(3)


def _version_of_stream(stream: str) -> str:
    """The version label a Lambda log stream name carries between its brackets."""
    assert "[" in stream and "]" in stream, f"log stream {stream!r} carries no [version] label"
    return stream[stream.index("[") + 1:stream.index("]")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
