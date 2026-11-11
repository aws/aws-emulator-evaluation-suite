"""python312-and-python313-handlers-run-asyncio-zoneinfo-and-sqlite3."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "python312-and-python313-handlers-run-asyncio-zoneinfo-and-sqlite3"
GROUP = "python-runtime"
SERVICES = ["lambda"]

_RUNTIMES = ["python3.12", "python3.13"]

_HANDLER = """\
import asyncio
import os
import sqlite3
import sys
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


async def _square(n):
    await asyncio.sleep(0)
    return n * n


async def _squares(ns):
    return await asyncio.gather(*(_square(n) for n in ns))


def handler(event, context):
    squares = asyncio.run(_squares(event["ns"]))
    new_york = ZoneInfo("America/New_York")
    summer = datetime(2024, 7, 1, 12, tzinfo=timezone.utc).astimezone(new_york)
    winter = datetime(2024, 1, 15, 12, tzinfo=timezone.utc).astimezone(new_york)
    path = "/tmp/" + context.aws_request_id + ".db"
    writer = sqlite3.connect(path)
    writer.execute("CREATE TABLE t (k TEXT PRIMARY KEY, v INTEGER)")
    rows = [("k%d" % i, n) for i, n in enumerate(squares)]
    writer.executemany("INSERT INTO t VALUES (?, ?)", rows)
    writer.commit()
    writer.close()
    reader = sqlite3.connect(path)
    total, count = reader.execute("SELECT SUM(v), COUNT(*) FROM t").fetchone()
    reader.close()
    os.remove(path)
    return {
        "version": list(sys.version_info[:2]),
        "implementation": sys.implementation.name,
        "squares": squares,
        "summer": [summer.isoformat(), summer.tzname()],
        "winter": [winter.isoformat(), winter.tzname()],
        "sqlite": [total, count, sqlite3.sqlite_version_info[0]],
    }
"""

_NS = [1, 2, 3, 4]
_SQUARES = [n * n for n in _NS]
_EXPECTED = {
    "implementation": "cpython",
    "squares": _SQUARES,
    "summer": ["2024-07-01T08:00:00-04:00", "EDT"],
    "winter": ["2024-01-15T07:00:00-05:00", "EST"],
    "sqlite": [sum(_SQUARES), len(_SQUARES), 3],
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Python 3.12 and 3.13 handlers run on CPython with asyncio, zoneinfo and sqlite3 working.

    asyncio.gather resolves, America/New_York yields EDT and EST, sqlite3 rows round-trip in /tmp.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
    """
    lam = ctx.client("lambda")
    role = _role_arn(ctx)
    code = _make_zip(_HANDLER)

    results = {}
    for runtime in _RUNTIMES:
        name = _function(ctx, lam, runtime, role, code)
        results[runtime] = _invoke_sync(lam, name, {"ns": _NS})

    for runtime, got in results.items():
        want_version = [int(p) for p in runtime.removeprefix("python").split(".")]
        assert got["version"] == want_version, (
            f"{runtime}: sys.version_info[:2] was {got['version']!r}, expected {want_version!r}"
        )
        for key, want in _EXPECTED.items():
            assert got[key] == want, f"{runtime}: {key} was {got[key]!r}, expected {want!r}"


# ===== helpers =====
def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", textwrap.dedent(code))
    return buf.getvalue()


def _role_arn(ctx) -> str:
    """An execution role allowed to write its logs; deleted in cleanup."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-lambda-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="exec"), "NoSuchEntity")
    )
    iam.put_role_policy(RoleName=name, PolicyName="exec", PolicyDocument=json.dumps(policy))
    return arn


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    A buffered log stream can flush and recreate the group after delete_function returns, so
    one delete is one round, not a teardown.
    """
    logs = ctx.client("logs")
    budget = _budget_s(ctx, 180.0)
    deadline = time.monotonic() + budget
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
                    f"log group {name} still present after {budget:.0f}s of deletes; "
                    f"{absent} clean reads"
                )
            time.sleep(interval_s)


def _function(ctx, lam, runtime, role, code) -> str:
    """Create a function, retried while its new role propagates, and wait until it is Active."""
    name = ctx.unique_name(f"sim2real-behav-{runtime.replace('.', '')}-")
    # LIFO: the log group is reaped after the function itself is deleted.
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    ctx.on_cleanup(
        _teardown(lambda: lam.delete_function(FunctionName=name), "ResourceNotFoundException")
    )
    kwargs = dict(
        FunctionName=name,
        Runtime=runtime,
        Handler="index.handler",
        Role=role,
        Code={"ZipFile": code},
        MemorySize=128,
        Timeout=30,
        Architectures=["x86_64"],
        Tags={"sim2real": CHECK},
    )
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        try:
            lam.create_function(**kwargs)
            break
        except ClientError as exc:
            if "cannot be assumed" in str(exc) and time.monotonic() < deadline:
                time.sleep(3)
                continue
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while creating {name}: {exc}") from exc
            raise
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=name)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {name} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return name
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"run budget ended before {name} was Active")
    raise AssertionError(f"{name} Active not met within the wait. Last: {last!r}")


def _invoke_sync(lam, fn, payload):
    resp = lam.invoke(
        FunctionName=fn,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload).encode(),
    )
    body = resp["Payload"].read()
    if resp.get("FunctionError"):
        raise AssertionError(
            f"Function {fn} returned FunctionError={resp['FunctionError']}: {body.decode()[:500]}"
        )
    assert resp["StatusCode"] == 200, (
        f"Function {fn}: synchronous Invoke StatusCode was {resp['StatusCode']!r}, expected 200"
    )
    return json.loads(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
