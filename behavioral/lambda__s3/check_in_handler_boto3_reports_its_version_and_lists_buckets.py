"""in-handler-boto3-reports-its-version-and-lists-buckets."""

from __future__ import annotations

import io
import json
import re
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "in-handler-boto3-reports-its-version-and-lists-buckets"
GROUP = "sdk-in-handler"
SERVICES = ["lambda", "s3"]

_VERSION = re.compile(r"1\.\d+\.\d+")

_HANDLER = """\
import boto3
import botocore


def handler(event, context):
    s3 = boto3.client("s3")
    listed = s3.list_buckets()
    location = s3.get_bucket_location(Bucket=event["bucket"])
    return {
        "boto3": boto3.__version__,
        "botocore": botocore.__version__,
        "list_status": listed["ResponseMetadata"]["HTTPStatusCode"],
        "listed_own_bucket": event["bucket"] in [b["Name"] for b in listed["Buckets"]],
        "owner_id_present": bool(listed.get("Owner", {}).get("ID")),
        "location": location.get("LocationConstraint"),
    }
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The SDK bundled in a python3.12 handler reports its version and calls S3 bucket operations.

    boto3.__version__ and botocore.__version__ are 1.x.y strings; ListBuckets returns the check's
    bucket with an owner id, and GetBucketLocation returns the bucket's region.

    Reference: https://docs.aws.amazon.com/lambda/latest/dg/lambda-python.html
    """
    s3 = ctx.client("s3")
    lam = ctx.client("lambda")
    bucket = ctx.unique_name("sim2real-behav-sdk-")
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    params = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)

    role = _role_arn(ctx)
    partition = role.split(":")[1]
    _grant(
        ctx,
        role,
        [
            {"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "s3:GetBucketLocation",
                "Resource": f"arn:{partition}:s3:::{bucket}",
            },
        ],
    )
    name = _function(ctx, lam, "python3.12", role, _make_zip(_HANDLER))
    # Retried while the new grants are not yet effective or ListBuckets does not yet show the
    # just-created bucket.
    error, got = _invoke_retrying(
        ctx,
        lam,
        name,
        {"bucket": bucket},
        lambda r: (
            "AccessDenied" in json.dumps(r[1]) or (r[0] is None and not r[1]["listed_own_bucket"])
        ),
    )
    assert error is None, f"the handler failed with FunctionError={error}: {json.dumps(got)[:500]}"

    for module in ("boto3", "botocore"):
        assert isinstance(got[module], str) and _VERSION.fullmatch(got[module]), (
            f"{module}.__version__ in the handler was {got[module]!r}, expected a 1.x.y string"
        )
    assert got["list_status"] == 200, f"ListBuckets status was {got['list_status']!r}"
    assert got["listed_own_bucket"] is True, f"ListBuckets omitted the bucket {bucket}: {got!r}"
    assert got["owner_id_present"] is True, f"ListBuckets carried no Owner.ID: {got!r}"
    want_location = None if ctx.region == "us-east-1" else ctx.region
    assert got["location"] == want_location, (
        f"GetBucketLocation returned {got['location']!r}, expected {want_location!r}"
    )


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


def _grant(ctx, role_arn: str, statements) -> None:
    """Attach ``statements`` to the role as a second inline policy; deleted in cleanup."""
    iam = ctx.client("iam")
    name = role_arn.rsplit("/", 1)[1]
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="grant"), "NoSuchEntity")
    )
    policy = {"Version": "2012-10-17", "Statement": list(statements)}
    iam.put_role_policy(RoleName=name, PolicyName="grant", PolicyDocument=json.dumps(policy))


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


def _invoke_retrying(ctx, lam, fn, payload, retry):
    """(FunctionError, payload) of a sync invoke, repeated while ``retry(result)`` within budget.

    A role's new inline grant can lag, so a denied first call is retried, never graded.
    """
    deadline = time.monotonic() + _budget_s(ctx, 90.0)
    while True:
        resp = lam.invoke(
            FunctionName=fn,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload).encode(),
        )
        assert resp["StatusCode"] == 200, (
            f"Function {fn}: synchronous Invoke StatusCode was {resp['StatusCode']!r}, expected 200"
        )
        result = (resp.get("FunctionError"), json.loads(resp["Payload"].read()))
        if not retry(result):
            return result
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {fn} still returned {result!r}")
            return result
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
