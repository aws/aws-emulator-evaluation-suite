"""concurrent-create-same-name-race."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-same-name-race"
GROUP = "concurrency"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous CreateDeliveryStream calls with the identical name resolve so exactly
    one succeeds and the other is rejected with ResourceInUseException and one of its two exact
    already-exists messages."""
    firehose = ctx.client("firehose")
    bucket_name, bucket_arn = _create_bucket(ctx)
    _role_name, role_arn, _policy_name = _create_firehose_role(ctx, bucket_arn)

    # IAM role trust propagation into Firehose is eventually consistent -- warm the role up
    # with a disposable stream/delete cycle so the real race below isn't spuriously rejected
    # with InvalidArgumentException ("unable to assume role") before IAM has propagated.
    teardown = {}
    _wait_role_ready(ctx, role_arn, bucket_arn, teardown)

    stream_name = ctx.unique_name("sim2real-behav-fh-race-")
    dest_config = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }

    barrier = threading.Barrier(2)

    def attempt():
        barrier.wait()
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
            )
            return ("ok", None, None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt) for _ in range(2)]
        results = [f.result() for f in futures]

    ctx.on_cleanup(lambda: _delete_stream(firehose, stream_name, teardown))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly one success, got {results}"
    assert len(failures) == 1, f"expected exactly one failure, got {results}"
    assert failures[0][1] == "ResourceInUseException", (
        f"expected the losing attempt to fail with ResourceInUseException, got {failures[0][1]}"
    )
    # AWS words the refusal for a taken name in one of these two ways, depending on how far the winner got.
    message = failures[0][2]
    assert message in {
        f"Firehose already exists: {stream_name}",
        f"Firehose {stream_name} under accountId {ctx.account} already exists",
    }, message

    # The single surviving stream should still resolve to a normal, usable ACTIVE stream.
    status = _wait_stream_active(ctx, stream_name)
    assert status == "ACTIVE", f"expected the surviving stream to reach ACTIVE, got {status}"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-bkt-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name, f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_firehose_role(ctx, bucket_arn, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [{
        "Effect": "Allow",
        "Action": [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject",
        ],
        "Resource": [bucket_arn, f"{bucket_arn}/*"],
    }]
    if extra_statements:
        statements.extend(extra_statements)

    policy_name = ctx.unique_name("sim2real-behav-fh-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn, policy_name


# Inside the 900 s firehose cleanup budget, one deadline shared by every stream teardown of a run.
_TEARDOWN_S = 780.0


def _delete_stream(firehose, name, shared):
    """Delete the stream and wait every 2 s until DescribeDeliveryStream answers not-found.
    DeleteDeliveryStream refuses a stream still CREATING with ResourceInUseException, which is retried;
    any other failure, or the shared deadline passing, raises."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_S)
    deleted = False
    while True:
        try:
            if not deleted:
                firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
                deleted = True
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present at the teardown deadline")
        time.sleep(2)


def _wait_role_ready(ctx, role_arn, bucket_arn, teardown, timeout_s: float = 120.0) -> None:
    """Poll IAM role assumability from Firehose's perspective by creating a disposable delivery
    stream (deleted once ACTIVE), retrying while Firehose reports the role as not
    yet assumable. This avoids the real create-stream race below flaking on IAM propagation
    lag rather than on the actual name-collision semantics under test."""
    firehose = ctx.client("firehose")
    probe_name = ctx.unique_name("sim2real-behav-fh-warmup-")
    dest_config = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=probe_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and "unable to assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(firehose, probe_name, teardown))
    # A stream still CREATING cannot be deleted, so the warm-up stream is deleted once ACTIVE.
    _wait_stream_active(ctx, probe_name)
    _delete_stream(firehose, probe_name, {})


def _wait_stream_active(ctx, name, timeout_s: float = 180.0) -> str:
    firehose = ctx.client("firehose")

    def probe():
        return firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    deadline = time.monotonic() + timeout_s
    status = probe()
    while status not in ("ACTIVE", "CREATING_FAILED") and time.monotonic() < deadline:
        time.sleep(5.0)
        status = probe()
    if status != "ACTIVE":
        raise AssertionError(f"stream did not reach ACTIVE within {timeout_s}s: {status}")
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
