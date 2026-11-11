"""tmp-not-shared-between-two-distinct-functions."""

from __future__ import annotations

import io
import json
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'tmp-not-shared-between-two-distinct-functions'
GROUP = 'python-runtime'
SERVICES = ['lambda']

_HANDLER = """\
import os


def handler(event, context):
    listing = sorted(os.listdir("/tmp"))
    with open(os.path.join("/tmp", event["marker"]), "w") as fh:
        fh.write(event["marker"])
    return {"tmp_listing": listing}
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
    policy = f"arn:{arn.split(':')[1]}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
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
    return json.loads(body) if body else None


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two distinct functions, each writing marker files to /tmp, never observe the other's
    files, while each finds one of its own earlier markers within a few invokes.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/foundation-filesystem.html
    """
    lam = ctx.client("lambda")
    role = _role_arn(ctx)
    code = _make_zip(_HANDLER)

    fn_a = ctx.unique_name("sim2real-behav-tmpiso-a-")
    fn_b = ctx.unique_name("sim2real-behav-tmpiso-b-")
    for name in (fn_a, fn_b):
        # Registered before create_function, so LIFO reaps the log group after the function
        # itself is deleted.
        ctx.on_cleanup(lambda name=name: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
        _create_function(
            lam, FunctionName=name, Runtime="python3.13", Handler="index.handler", Role=role,
            Code={"ZipFile": code}, MemorySize=128, Timeout=15, Tags={"sim2real": CHECK},
        )
        ctx.on_cleanup(lambda name=name: _cleanup_fn(lam, name))
        _wait_active(lam, name)

    # Interleaved invokes, each writing a fresh marker. Every listing is read before the
    # invoke writes, so a marker it holds was written by an earlier invoke.
    rounds = 8
    seen = {fn_a: [], fn_b: []}
    for i in range(rounds):
        for fn, own in ((fn_a, "a"), (fn_b, "b")):
            got = _invoke_sync(lam, fn, {"marker": f"marker-{own}-{i}.txt"})
            seen[fn].append(got["tmp_listing"])

    for fn, own, other in ((fn_a, "a", "b"), (fn_b, "b", "a")):
        leaked = sorted({m for listing in seen[fn] for m in listing if m.startswith(f"marker-{other}-")})
        assert not leaked, (
            f"{fn}'s /tmp held the other function's markers {leaked!r}; /tmp belongs to one "
            "function's execution environment"
        )
        # Positive control: some invoke of this function finds a marker an earlier one of its own
        # invokes wrote, so the absence above is isolation, not a /tmp that never persists.
        repeats = [i for i, listing in enumerate(seen[fn])
                   if any(m.startswith(f"marker-{own}-") for m in listing)]
        assert repeats, (
            f"{fn} never found one of its own earlier markers across {rounds} invokes; listings: "
            f"{seen[fn]!r}"
        )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
