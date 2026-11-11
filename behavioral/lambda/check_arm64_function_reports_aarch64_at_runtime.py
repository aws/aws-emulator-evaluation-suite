"""arm64-function-reports-aarch64-at-runtime."""

from __future__ import annotations

import io
import json
import os
import textwrap
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "arm64-function-reports-aarch64-at-runtime"
GROUP = 'compute'
SERVICES = ['lambda']

# One zip, two functions. The ONLY difference between the two functions is Architectures, so any
# difference in what the handler reports is attributable to the architecture and nothing else.
HANDLER = """\
import os
import platform
import struct
import sys


def handler(event, context):
    return {
        "machine": platform.machine(),
        "uname_machine": os.uname().machine,
        "maxsize": sys.maxsize,
        "byteorder": sys.byteorder,
        "pointer_bytes": struct.calcsize("P"),
    }
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}
_BASIC_EXEC = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_ROLE_NOT_READY = "The role defined for the function cannot be assumed by Lambda."


def _role_arn(ctx):
    """Create this run's own Lambda execution role (once per run) and return its ARN."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_BASIC_EXEC))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function(lam, **kwargs):
    """CreateFunction, retried while a freshly created execution role is still propagating."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_ready = (err.get("Code") == "InvalidParameterValueException"
                         and err.get("Message") == _ROLE_NOT_READY)
            if not not_ready or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        # Lambda creates /aws/lambda/<fn> on FIRST INVOKE, so it can materialise after this
        # delete; the final account sweep is the arbiter, not this call.
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll(probe, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = probe()
        if got:
            return got
        time.sleep(interval_s)
    return None


def _wait_active(lam, fn, timeout_s=180):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _deploy(ctx, lam, arch):
    name = ctx.unique_name(f"sim2real-behav-{arch.replace('_', '')}-")
    _create_function(lam,
        FunctionName=name, Runtime="python3.12", Handler="index.handler",
        Role=_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        Architectures=[arch], MemorySize=128, Timeout=30,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    return name


def _body(lam, fn):
    resp = lam.invoke(FunctionName=fn, Payload=b"{}")
    payload = resp["Payload"].read()
    assert resp["StatusCode"] == 200, f"{fn}: StatusCode {resp['StatusCode']!r} {payload!r}"
    assert "FunctionError" not in resp, (
        f"{fn} failed with FunctionError={resp.get('FunctionError')!r}: {payload!r}"
    )
    return json.loads(payload)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An arm64 function's running code reports machine aarch64 and its x86_64 twin from the same zip
    reports x86_64, so Architectures controls where the handler executes, not only the echoed
    configuration."""
    lam = ctx.client("lambda")

    arm = _deploy(ctx, lam, "arm64")
    x86 = _deploy(ctx, lam, "x86_64")
    arm_cfg = _wait_active(lam, arm)
    x86_cfg = _wait_active(lam, x86)

    assert arm_cfg["Architectures"] == ["arm64"], (
        f"configuration disagrees with the request: {arm_cfg.get('Architectures')!r}"
    )
    assert x86_cfg["Architectures"] == ["x86_64"], (
        f"configuration disagrees with the request: {x86_cfg.get('Architectures')!r}"
    )

    arm_body = _body(lam, arm)
    x86_body = _body(lam, x86)

    assert arm_body["machine"] == "aarch64", (
        f"the arm64 function reported platform.machine()=={arm_body['machine']!r} at runtime, not "
        f"'aarch64' — the runtime is not executing on the architecture that was configured"
    )
    assert x86_body["machine"] == "x86_64", (
        f"the x86_64 function reported platform.machine()=={x86_body['machine']!r} at runtime"
    )
    assert arm_body["machine"] != x86_body["machine"], (
        f"both architectures reported the same machine {arm_body['machine']!r} — Architectures is "
        f"being stored but not honoured by the execution environment"
    )
    # os.uname() is a second, independent syscall-level source for the same fact: an emulator that
    # only monkey-patches platform.machine() is caught here.
    assert arm_body["uname_machine"] == "aarch64", (
        f"os.uname().machine on the arm64 function was {arm_body['uname_machine']!r}, and it must "
        f"agree with platform.machine() — they read the same kernel field"
    )
    assert x86_body["uname_machine"] == "x86_64", (
        f"os.uname().machine on the x86_64 function was {x86_body['uname_machine']!r}"
    )

    # Both are 64-bit little-endian, so the machine string is the ONLY thing that may differ.
    for label, body in (("arm64", arm_body), ("x86_64", x86_body)):
        assert body["maxsize"] == 2 ** 63 - 1, (
            f"{label} reported sys.maxsize={body['maxsize']!r}; both Lambda architectures are 64-bit"
        )
        assert body["pointer_bytes"] == 8, (
            f"{label} reported an {body['pointer_bytes']!r}-byte pointer; both are 64-bit"
        )
        assert body["byteorder"] == "little", (
            f"{label} reported byteorder={body['byteorder']!r}; both are little-endian"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
