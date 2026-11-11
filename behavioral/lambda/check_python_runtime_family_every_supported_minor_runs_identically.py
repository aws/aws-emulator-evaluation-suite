"""python-runtime-family-every-supported-minor-runs-identically."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'python-runtime-family-every-supported-minor-runs-identically'
GROUP = 'python-runtime'
SERVICES = ['lambda']

# Every python3.x identifier the AWS Lambda runtimes page
# (https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) lists as supported and not
# at its deprecation date, so function creation is not blocked. Pairs each with an architecture so an architecture-neutral
# handler is exercised on both, with no single identifier or arch dominant.
_RUNTIMES = [
    ("python3.11", "arm64"),
    ("python3.12", "x86_64"),
    ("python3.13", "arm64"),
    ("python3.14", "x86_64"),
]

_HANDLER = """\
import os
import platform
import sys


def handler(event, context):
    return {
        "version": list(sys.version_info[:2]),
        "machine": platform.machine(),
        "execution_env": os.environ.get("AWS_EXECUTION_ENV"),
        "computed": sum(range(event["n"])),
    }
"""


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _role_arn(ctx) -> str:
    """An execution role this check creates and deletes in cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    policy = f"arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy), "NoSuchEntity"))
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while the role this check just created propagates in IAM."""
    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _cleanup_fn(lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush and recreate the group after delete_function returns, so
    one delete is one round, not a teardown.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn, InvocationType="RequestResponse", Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    assert resp["StatusCode"] == 200, (
        f"Function {fn}: synchronous Invoke StatusCode was {resp['StatusCode']!r}, expected 200"
    )
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:representation", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """The same handler creates and invokes identically under every supported python3.x
    identifier; each function's own reported version and AWS_EXECUTION_ENV match its Runtime.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
    Reference: https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunction.html#API_CreateFunction_RequestSyntax
    """
    lam = ctx.client("lambda")
    role = _role_arn(ctx)
    code = _make_zip(_HANDLER)

    results = {}
    for runtime, arch in _RUNTIMES:
        name = ctx.unique_name(f"sim2real-behav-fam-{runtime.replace('.', '')}-")
        # Registered before create_function, so LIFO reaps the log group after the function
        # itself is deleted.
        ctx.on_cleanup(lambda name=name: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
        _create_function(
            lam, FunctionName=name, Runtime=runtime, Handler="index.handler", Role=role,
            Code={"ZipFile": code}, MemorySize=128, Timeout=15, Architectures=[arch],
            Tags={"sim2real": CHECK},
        )
        ctx.on_cleanup(lambda name=name: _cleanup_fn(lam, name))
        _wait_active(lam, name)
        got = _invoke_sync(lam, name, {"n": 10})
        results[runtime] = (arch, got)

    for runtime, (arch, got) in results.items():
        want_version = [int(p) for p in runtime.removeprefix("python").split(".")]
        assert got["version"] == want_version, (
            f"{runtime}: sys.version_info[:2] was {got['version']!r}, expected {want_version!r}"
        )
        want_machine = "aarch64" if arch == "arm64" else "x86_64"
        assert got["machine"] == want_machine, (
            f"{runtime}/{arch}: platform.machine() was {got['machine']!r}, expected {want_machine!r}"
        )
        assert got["execution_env"] == f"AWS_Lambda_{runtime}", (
            f"{runtime}: AWS_EXECUTION_ENV was {got['execution_env']!r}, "
            f"expected 'AWS_Lambda_{runtime}'"
        )
        assert got["computed"] == 45, (
            f"{runtime}: sum(range(10)) returned {got['computed']!r}, expected 45"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
