"""metric-stream-server-side-delivery-status-managed."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "metric-stream-server-side-delivery-status-managed"
GROUP = "server-side"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A metric stream on a real Firehose delivery stream reads back running with the Put Arn, FirehoseArn
    and RoleArn from GetMetricStream and ListMetricStreams, and after StopMetricStreams both report
    stopped, all from CloudWatch's own control plane."""
    cw = ctx.client("cloudwatch")
    infra = _provision_metric_stream_infra(ctx)
    name = ctx.unique_name("sim2real-ms-")
    resp = cw.put_metric_stream(
        Name=name,
        FirehoseArn=infra["firehose_arn"],
        RoleArn=infra["role_arn"],
        OutputFormat="json",
    )
    ctx.on_cleanup(lambda: cw.delete_metric_stream(Name=name))
    stream_arn = resp["Arn"]

    # A freshly created stream is running by default -- verify purely via the
    # CloudWatch control plane, without ever calling firehose:DescribeDeliveryStream.
    described = cw.get_metric_stream(Name=name)
    assert described["State"] == "running", f"expected new metric stream 'running', got {described['State']!r}"
    assert described["Arn"] == stream_arn, f"GetMetricStream Arn {described['Arn']!r} != PutMetricStream Arn {stream_arn!r}"
    assert described["FirehoseArn"] == infra["firehose_arn"], (
        f"GetMetricStream FirehoseArn {described['FirehoseArn']!r} != {infra['firehose_arn']!r}"
    )
    assert described["RoleArn"] == infra["role_arn"], f"GetMetricStream RoleArn {described['RoleArn']!r} != {infra['role_arn']!r}"

    listed = _find_stream_entry(cw, name)
    assert listed is not None, "ListMetricStreams did not surface the new stream"
    assert listed["State"] == "running", f"ListMetricStreams entry expected 'running', got {listed['State']!r}"
    assert listed["Arn"] == stream_arn, f"ListMetricStreams Arn {listed['Arn']!r} != {stream_arn!r}"

    # Drive it through a real transition and confirm both server-side views converge
    # on the new terminal status without any client-side polling of Firehose.
    cw.stop_metric_streams(Names=[name])
    stopped = _poll_until(
        lambda: cw.get_metric_stream(Name=name)["State"],
        lambda state: state == "stopped",
        timeout_s=30,
        interval_s=1,
    )
    assert stopped == "stopped", f"GetMetricStream State expected 'stopped' after StopMetricStreams, got {stopped!r}"
    listed_after = _find_stream_entry(cw, name)
    assert listed_after is not None, "ListMetricStreams no longer surfaces the stopped stream"
    assert listed_after["State"] == "stopped", f"ListMetricStreams entry expected 'stopped', got {listed_after['State']!r}"


def _find_stream_entry(cw, name: str):
    # ListMetricStreams has no botocore paginator config; NextToken is manual.
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = cw.list_metric_streams(**kwargs)
        for entry in page.get("Entries", []):
            if entry["Name"] == name:
                return entry
        next_token = page.get("NextToken")
        if not next_token:
            return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _provision_metric_stream_infra(ctx) -> dict:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    firehose = ctx.client("firehose")

    bucket_name = ctx.unique_name("sim2real-cwms-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    fh_role_name = ctx.unique_name("sim2real-fhrole-")
    fh_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    fh_role_arn = iam.create_role(RoleName=fh_role_name, AssumeRolePolicyDocument=json.dumps(fh_trust))["Role"]["Arn"]
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
    ms_role_arn = iam.create_role(RoleName=ms_role_name, AssumeRolePolicyDocument=json.dumps(ms_trust))["Role"]["Arn"]
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
