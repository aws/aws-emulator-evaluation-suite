"""concurrent-put-metric-stream-start-stop-race."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-put-metric-stream-start-stop-race"
GROUP = "concurrency"
SERVICES = ["cloudwatch"]

_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]
_VALID_STATES = {"running", "stopped"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent Start/Stop calls on one metric stream settle on a valid State that stays put,
    and sequential Stop and Start calls each leave the State the last call set."""
    cw = ctx.client("cloudwatch")
    infra = _provision_metric_stream_infra(ctx)
    name = ctx.unique_name("sim2real-ms-")
    cw.put_metric_stream(
        Name=name,
        FirehoseArn=infra["firehose_arn"],
        RoleArn=infra["role_arn"],
        OutputFormat="json",
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))

    # New streams are created running (documented default) -- confirm the baseline.
    assert cw.get_metric_stream(Name=name)["State"] == "running"

    # The order in which the client receives the two responses is not the order the
    # service applied them, so a race round accepts either final State but requires
    # it to be one of the two and to stay the same across reads ~1 s apart.
    for round_num in range(3):
        barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            start_future = pool.submit(_aligned_call, barrier, cw.start_metric_streams, name)
            stop_future = pool.submit(_aligned_call, barrier, cw.stop_metric_streams, name)
            start_future.result()
            stop_future.result()

        reads = []
        deadline = time.monotonic() + 30
        while True:
            time.sleep(1)
            reads.append(cw.get_metric_stream(Name=name)["State"])
            if (len(reads) >= 3 and len(set(reads[-3:])) == 1) or time.monotonic() > deadline:
                break
        assert set(reads) <= _VALID_STATES, (
            f"round {round_num}: State outside {sorted(_VALID_STATES)}: {reads}"
        )
        assert len(reads) >= 3 and len(set(reads[-3:])) == 1, (
            f"round {round_num}: State never held across three reads ~1 s apart: {reads}"
        )

    # Sequential arm: with no race, the State is the one the last call set. Leaving the race's
    # State first makes both calls real transitions, never a no-op on the current State.
    stop, start = (cw.stop_metric_streams, "stopped"), (cw.start_metric_streams, "running")
    sequence = (stop, start) if reads[-1] == "running" else (start, stop)
    for op, expected_state in sequence:
        op(Names=[name])
        observed = _poll_until(
            lambda: cw.get_metric_stream(Name=name)["State"],
            lambda state, want=expected_state: state == want,
            timeout_s=30,
            interval_s=1,
        )
        assert observed == expected_state, (
            f"sequential: expected State {expected_state!r} after the last call "
            f"but observed {observed!r}"
        )
        time.sleep(1)
        assert cw.get_metric_stream(Name=name)["State"] == expected_state


def _aligned_call(barrier, op, name: str) -> None:
    barrier.wait(timeout=30)
    op(Names=[name])


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _provision_metric_stream_infra(ctx) -> dict:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-cwms-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _TAGS})
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    fh_role_name = ctx.unique_name("sim2real-fhrole-")
    fh_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    fh_role_arn = iam.create_role(
        RoleName=fh_role_name, AssumeRolePolicyDocument=json.dumps(fh_trust), Tags=_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fh_role_name))
    fh_policy_name = "s3-access"
    iam.put_role_policy(
        RoleName=fh_role_name,
        PolicyName=fh_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:GetBucketLocation",
                            "s3:ListBucket",
                            "s3:AbortMultipartUpload",
                            "s3:GetObject",
                        ],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fh_role_name, PolicyName=fh_policy_name))

    ds_name = ctx.unique_name("sim2real-ds-")
    firehose_arn = _retry_until_ok(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=ds_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={"RoleARN": fh_role_arn, "BucketARN": bucket_arn},
            Tags=_TAGS,
        )["DeliveryStreamARN"],
        timeout_s=90,
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=ds_name))

    deadline = time.monotonic() + 180
    while True:
        status = firehose.describe_delivery_stream(DeliveryStreamName=ds_name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ]
        if status == "ACTIVE":
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"firehose delivery stream {ds_name} never became ACTIVE (last: {status})")
        time.sleep(5)

    ms_role_name = ctx.unique_name("sim2real-msrole-")
    ms_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "streams.metrics.cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    ms_role_arn = iam.create_role(
        RoleName=ms_role_name, AssumeRolePolicyDocument=json.dumps(ms_trust), Tags=_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ms_role_name))
    ms_policy_name = "firehose-write"
    iam.put_role_policy(
        RoleName=ms_role_name,
        PolicyName=ms_policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"], "Resource": firehose_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=ms_role_name, PolicyName=ms_policy_name))

    _ = account_id  # kept for clarity; ARNs above already carry the account implicitly
    return {"firehose_arn": firehose_arn, "role_arn": ms_role_arn}


def _retry_until_ok(fn, *, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - IAM role propagation lag surfaces various transient errors
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_exc}")


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        keys = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
