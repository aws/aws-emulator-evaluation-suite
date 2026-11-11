"""tmp-not-shared-between-concurrent-invocations."""

from __future__ import annotations

import concurrent.futures
import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "tmp-not-shared-between-concurrent-invocations"
GROUP = 'ephemeral_storage'
SERVICES = ['lambda']

# Seconds each invocation holds its sandbox open, so the two are in flight together.
HOLD_S = 8
EPHEMERAL_MIB = 512

HANDLER = """\
import os
import time


def _read(path):
    with open(path) as fh:
        return fh.read()


def handler(event, context):
    marker = event["marker"]
    path = os.path.join("/tmp", marker)
    with open(path, "w") as fh:
        fh.write(marker)
    deadline = time.time() + float(event["hold_s"])
    while time.time() < deadline:
        time.sleep(0.2)
    return {
        "marker": marker,
        "request_id": context.aws_request_id,
        "listing": sorted(os.listdir("/tmp")),
        "own_file_content": _read(path),
    }
"""


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLES: dict = {}


def _exec_role_arn(ctx) -> str:
    """An execution role this check creates (once per run) and deletes in cleanup."""
    if id(ctx) in _ROLES:
        return _ROLES[id(ctx)]
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
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy))
    _ROLES[id(ctx)] = arn
    return arn


def _create_function_when_role_ready(lam, **kwargs):
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


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function_concurrency(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
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


def _wait_active(lam, fn, timeout_s=120):
    def _probe():
        cfg = lam.get_function_configuration(FunctionName=fn)
        if cfg["State"] == "Failed":
            raise AssertionError(f"{fn} entered State=Failed: {cfg.get('StateReason')}")
        return cfg if cfg["State"] == "Active" else None

    cfg = _poll(_probe, timeout_s)
    assert cfg is not None, f"{fn} did not reach State=Active within {timeout_s}s"
    return cfg


def _run_concurrent(fns, timeout_s=120):
    results = [None] * len(fns)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns))) as ex:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
            idx = future_to_idx[fut]
            try:
                results[idx] = fut.result()
            except Exception as exc:  # surfaced by the caller with the index
                results[idx] = exc
    return results


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two simultaneous invocations each see their own /tmp file and not the other's, because /tmp
    is per execution environment.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/configuration-ephemeral-storage.html
    """
    lam = ctx.client("lambda")
    fn = ctx.unique_name("sim2real-behav-fn-")
    _create_function_when_role_ready(lam,
        FunctionName=fn, Runtime="python3.12", Handler="index.handler",
        Role=_exec_role_arn(ctx), Code={"ZipFile": _make_zip(HANDLER)},
        MemorySize=256, Timeout=60, EphemeralStorage={"Size": EPHEMERAL_MIB},
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, fn))
    cfg = _wait_active(lam, fn)
    assert cfg["EphemeralStorage"]["Size"] == EPHEMERAL_MIB, (
        f"EphemeralStorage must round-trip, got {cfg.get('EphemeralStorage')}"
    )

    # Two slots, so neither invocation is throttled or queued behind the other.
    conc = lam.put_function_concurrency(FunctionName=fn, ReservedConcurrentExecutions=2)
    assert conc["ReservedConcurrentExecutions"] == 2, conc

    markers = ["sim2real-tmp-a", "sim2real-tmp-b"]

    def _invoker(marker):
        def _call():
            resp = lam.invoke(
                FunctionName=fn,
                Payload=json.dumps({"marker": marker, "hold_s": HOLD_S}).encode(),
            )
            payload = resp["Payload"].read()
            assert resp["StatusCode"] == 200, f"{marker}: {resp['StatusCode']} {payload!r}"
            assert "FunctionError" not in resp, (
                f"{marker} failed with {resp.get('FunctionError')}: {payload!r}"
            )
            return json.loads(payload)
        return _call

    results = _run_concurrent([_invoker(m) for m in markers], timeout_s=120)
    for marker, res in zip(markers, results):
        assert not isinstance(res, BaseException), f"invocation {marker} raised {res!r}"

    a, b = results
    assert a["marker"] == markers[0] and b["marker"] == markers[1], (a["marker"], b["marker"])
    assert a["request_id"] != b["request_id"], (
        f"both invocations reported the same aws_request_id {a['request_id']} — they were not two "
        f"distinct invocations"
    )

    for own, other in ((a, b), (b, a)):
        assert own["own_file_content"] == own["marker"], own
        assert own["marker"] in own["listing"], (
            f"{own['marker']} could not see the file it had just written: {own['listing']}"
        )
        assert other["marker"] not in own["listing"], (
            f"invocation {own['marker']} saw {other['marker']} in its own /tmp listing "
            f"({own['listing']}) — /tmp is shared between concurrent execution environments"
        )

    # Control: a later invoke still works, and reserved concurrency is still readable.
    solo = lam.invoke(
        FunctionName=fn, Payload=json.dumps({"marker": "sim2real-tmp-c", "hold_s": 0}).encode()
    )
    assert solo["StatusCode"] == 200 and "FunctionError" not in solo, solo.get("FunctionError")
    solo_marker = json.loads(solo["Payload"].read())["marker"]
    assert solo_marker == "sim2real-tmp-c", (
        f"expected the solo invocation to echo marker sim2real-tmp-c, got {solo_marker!r}"
    )
    solo_conc = lam.get_function_concurrency(FunctionName=fn)["ReservedConcurrentExecutions"]
    assert solo_conc == 2, (
        f"expected ReservedConcurrentExecutions to still read back as 2 after the concurrent "
        f"invocations, got {solo_conc}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
