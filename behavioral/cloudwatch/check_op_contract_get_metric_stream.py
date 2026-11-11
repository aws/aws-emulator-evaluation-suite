"""op-contract-getMetricStream."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-getMetricStream"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetMetricStream reflects the stream's live State (running/stopped) and configured
    FirehoseArn/RoleArn/OutputFormat; querying a name that was never created is
    ResourceNotFoundException."""
    cw = ctx.client("cloudwatch")
    infra = _create_metric_stream_infra(ctx)
    stream_name = infra["stream_name"]

    described = cw.get_metric_stream(Name=stream_name)
    assert described["State"] == "running", f"expected State=running, got {described['State']!r}"
    assert described["OutputFormat"] == "json", (
        f"expected OutputFormat=json, got {described['OutputFormat']!r}"
    )
    assert described["FirehoseArn"] == infra["firehose_arn"], (
        f"expected FirehoseArn={infra['firehose_arn']!r}, got {described['FirehoseArn']!r}"
    )
    assert described["RoleArn"] == infra["role_arn"], (
        f"expected RoleArn={infra['role_arn']!r}, got {described['RoleArn']!r}"
    )
    assert described["Name"] == stream_name, (
        f"expected Name={stream_name!r}, got {described['Name']!r}"
    )
    assert described["Arn"].endswith(f"metric-stream/{stream_name}"), (
        f"expected Arn to end with metric-stream/{stream_name}, got {described['Arn']!r}"
    )

    cw.stop_metric_streams(Names=[stream_name])
    stopped = _poll_until(
        lambda: cw.get_metric_stream(Name=stream_name)["State"],
        lambda s: s == "stopped",
        timeout_s=30,
        description=f"metric stream {stream_name} reaching state stopped",
    )
    assert stopped == "stopped", f"expected State=stopped, got {stopped!r}"

    cw.start_metric_streams(Names=[stream_name])
    running = _poll_until(
        lambda: cw.get_metric_stream(Name=stream_name)["State"],
        lambda s: s == "running",
        timeout_s=30,
        description=f"metric stream {stream_name} reaching state running",
    )
    assert running == "running", f"expected State=running, got {running!r}"

    bogus_name = ctx.unique_name("sim2real-cw-stream-missing-")
    code, message = _client_error(lambda: cw.get_metric_stream(Name=bogus_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a metric stream that was never created, got {code}"
    )
    expected_message = ""  # AWS returns this refusal with an empty message
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
def _client_error(fn):
    """Call fn; return the (code, message) of the ClientError it raises.

    Raises AssertionError when the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {result!r}")
    return result


def _create_bucket(ctx) -> dict[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cw-ms-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's historical default region and CreateBucket rejects an explicit
        # LocationConstraint for it; every other region requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_role(ctx, trust_service: str, inline_policy: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cw-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cw-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Role"]["Arn"]


def _create_firehose_to_s3(ctx, bucket_arn: str, firehose_role_arn: str) -> str:
    firehose = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-cw-fh-")
    deadline = time.monotonic() + 45
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": firehose_role_arn,
                    "BucketARN": bucket_arn,
                },
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except Exception as err:  # IAM role propagation delay
            last_err = err
            time.sleep(2)
    else:
        raise AssertionError(f"could not create firehose delivery stream: {last_err}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))

    def _active():
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)
        return desc["DeliveryStreamDescription"]["DeliveryStreamStatus"]

    status = _poll_until(_active, lambda s: s == "ACTIVE", timeout_s=90, interval_s=3)
    assert status == "ACTIVE", f"firehose delivery stream never became ACTIVE (status={status})"
    return firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamARN"]


def _create_metric_stream_infra(ctx) -> dict[str, str]:
    bucket = _create_bucket(ctx)
    firehose_role_arn = _create_role(
        ctx,
        "firehose.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:AbortMultipartUpload",
                        "s3:GetBucketLocation",
                        "s3:GetObject",
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                    ],
                    "Resource": [bucket["arn"], f"{bucket['arn']}/*"],
                }
            ],
        },
    )
    firehose_arn = _create_firehose_to_s3(ctx, bucket["arn"], firehose_role_arn)

    metric_stream_role_arn = _create_role(
        ctx,
        "streams.metrics.cloudwatch.amazonaws.com",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["firehose:PutRecord", "firehose:PutRecordBatch"],
                    "Resource": firehose_arn,
                }
            ],
        },
    )

    cw = ctx.client("cloudwatch")
    stream_name = ctx.unique_name("sim2real-cw-metricstream-")
    deadline = time.monotonic() + 45
    last_err = None
    while time.monotonic() < deadline:
        try:
            cw.put_metric_stream(
                Name=stream_name,
                FirehoseArn=firehose_arn,
                RoleArn=metric_stream_role_arn,
                OutputFormat="json",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except Exception as err:  # IAM role propagation delay
            last_err = err
            time.sleep(2)
    else:
        raise AssertionError(f"could not create metric stream: {last_err}")
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(cw, stream_name))

    return {
        "stream_name": stream_name,
        "firehose_arn": firehose_arn,
        "role_arn": metric_stream_role_arn,
    }


def _delete_stream_ignore_missing(cw, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cw.delete_metric_stream(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
