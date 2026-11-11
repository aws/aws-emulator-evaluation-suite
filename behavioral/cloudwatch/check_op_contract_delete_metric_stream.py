"""op-contract-deleteMetricStream."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "op-contract-deleteMetricStream"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMetricStream permanently removes a running metric stream (GetMetricStream then
    raises ResourceNotFoundException); deleting a name that never existed is a no-op success."""
    cw = ctx.client("cloudwatch")
    infra = _create_metric_stream_infra(ctx)
    stream_name = infra["stream_name"]

    described = cw.get_metric_stream(Name=stream_name)
    assert described["State"] == "running", (
        f"expected a freshly created metric stream to be running, got {described['State']!r}"
    )
    assert described["FirehoseArn"] == infra["firehose_arn"], (
        f"expected GetMetricStream to echo the configured FirehoseArn "
        f"{infra['firehose_arn']!r}, got {described['FirehoseArn']!r}"
    )

    # No-op-on-missing-name is asserted before the real stream is deleted, so the
    # positive control below can prove the no-op left the still-live stream untouched.
    bogus_name = ctx.unique_name("sim2real-cw-stream-missing-")
    noop = cw.delete_metric_stream(Name=bogus_name)
    assert noop["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected deleting a never-existing metric stream to be a no-op success, got {noop!r}"
    )
    still_missing_code, still_missing_message = _error(lambda: cw.get_metric_stream(Name=bogus_name))
    assert still_missing_code == "ResourceNotFoundException", (
        f"expected the never-existing name to remain absent after the no-op delete, "
        f"got {still_missing_code}"
    )
    # real AWS sends this refusal with an empty message
    assert still_missing_message == "", (
        f"expected an empty refusal message, got {still_missing_message!r}"
    )
    unaffected = cw.get_metric_stream(Name=stream_name)["State"]
    assert unaffected == "running", (
        f"expected the no-op delete of an unrelated name to leave the real stream "
        f"running, got {unaffected!r}"
    )

    cw.delete_metric_stream(Name=stream_name)

    _poll_until(
        lambda: [e["Name"] for e in cw.list_metric_streams().get("Entries", [])],
        lambda names: stream_name not in names,
        timeout_s=30,
        description="ListMetricStreams no longer listing the deleted stream",
    )
    code, message = _error(lambda: cw.get_metric_stream(Name=stream_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetMetricStream after delete, got {code}"
    )
    # real AWS sends this refusal with an empty message
    assert message == "", f"expected an empty refusal message, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Return (code, message) of the ClientError fn raises. A SUCCESS is an AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result) and time.monotonic() < deadline:
        time.sleep(interval_s)
        result = probe()
    if not predicate(result):
        raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {result!r}")
    return result


def _create_bucket(ctx) -> dict[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cw-ms-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
        Tags=[{"Key": "sim2real-owner", "Value": "op-contract-deleteMetricStream"}],
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
                Tags=[{"Key": "sim2real-owner", "Value": "op-contract-deleteMetricStream"}],
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
                Tags=[{"Key": "sim2real-owner", "Value": "op-contract-deleteMetricStream"}],
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
