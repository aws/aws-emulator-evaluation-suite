"""python-subprocess-runs-a-command."""
from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "python-subprocess-runs-a-command"
GROUP = "python-runtime"
SERVICES = ["lambda"]

_RUNTIME = "python3.12"
_SOURCE_FILE = "index.py"

_HANDLER = """\
import subprocess


def handler(event, context):
    proc = subprocess.run(["/bin/sh", "-c", "echo $((6*7))"], capture_output=True, text=True,
                          timeout=20)
    return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Python handler can spawn a child process: /bin/sh evaluates an arithmetic expansion and
    subprocess.run captures its stdout and exit status.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html
    """
    role = _execution_role(ctx)
    fn = _function(ctx, role["arn"], _HANDLER)
    out = _invoke_ok(ctx, fn["name"])
    assert out["returncode"] == 0, (
        f"/bin/sh -c 'echo $((6*7))' must exit 0, got {out['returncode']!r} "
        f"(stderr {out['stderr']!r})")
    assert out["stdout"] == "42\n", f"the child must print '42\\n', got {out['stdout']!r}"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, done, *, timeout_s, interval_s, what):
    """``probe()`` until ``done(result)``; raises naming ``what`` and the last result on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting until {what}; last={last!r}")
        time.sleep(interval_s)


def _zip(code: str, extra=None) -> bytes:
    """The deployment package: the handler module plus ``extra`` files keyed by archive path."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_SOURCE_FILE, textwrap.dedent(code))
        for path, body in (extra or {}).items():
            zf.writestr(path, body)
    return buf.getvalue()


def _execution_role(ctx) -> dict:
    """A Lambda execution role with no permissions: the handler calls no AWS API, and without a
    logs: grant the function never creates a log group that could outlive the check."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return {"name": name, "arn": role["Arn"], "id": role["RoleId"]}


def _function(ctx, role_arn, code, *, timeout=60, memory=256, extra=None, environment=None) -> dict:
    """A function from ``code``, created through the role-propagation window and Active."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    kwargs = {"FunctionName": name, "Runtime": _RUNTIME, "Handler": "index.handler",
              "Role": role_arn, "Code": {"ZipFile": _zip(code, extra)}, "Timeout": timeout,
              "MemorySize": memory, "Tags": {"sim2real": CHECK}}
    if environment:
        kwargs["Environment"] = {"Variables": environment}

    def create():
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (err["Code"] == "InvalidParameterValueException"
                    and "cannot be assumed" in err.get("Message", "")):
                return None
            raise

    out = _poll(create, lambda r: r is not None, timeout_s=90, interval_s=3,
                what="CreateFunction accepts the fresh execution role")
    ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                             "ResourceNotFoundException"))
    conf = _poll(lambda: lam.get_function_configuration(FunctionName=name),
                 lambda c: c.get("State", "Active") in ("Active", "Failed"),
                 timeout_s=90, interval_s=1, what=f"function {name} leaves Pending")
    assert conf.get("State", "Active") == "Active", (
        f"function {name} ended {conf.get('State')!r}: {conf.get('StateReason')!r}")
    return {"name": name, "arn": out["FunctionArn"]}


def _invoke(ctx, fn, event=None, lam=None) -> tuple:
    """(FunctionError or None, decoded payload) of one RequestResponse invoke of ``event``."""
    lam = lam or ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn, InvocationType="RequestResponse",
                      Payload=json.dumps(event or {}).encode())
    raw = resp["Payload"].read()
    return resp.get("FunctionError"), (json.loads(raw) if raw else None)


def _invoke_ok(ctx, fn, event=None) -> dict:
    """The payload of one invoke that must succeed; a FunctionError raises with the payload."""
    err, out = _invoke(ctx, fn, event)
    assert err is None, f"the function failed: {err!r} {out!r}"
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
