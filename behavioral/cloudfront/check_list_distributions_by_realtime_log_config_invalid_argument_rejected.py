"""list-distributions-by-realtime-log-config-invalid-argument-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-realtime-log-config-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByRealtimeLogConfig with neither RealtimeLogConfigName nor
    RealtimeLogConfigArn set is rejected with InvalidArgument, while the same call against a
    real, freshly created (and unused) real-time log config name succeeds.
    """
    cf = ctx.client("cloudfront")
    config_name = _create_realtime_log_config(ctx)

    ok = cf.list_distributions_by_realtime_log_config(RealtimeLogConfigName=config_name)
    quantity = ok["DistributionList"]["Quantity"]
    assert quantity == 0, f"expected Quantity 0 for a freshly created, unused config, got {quantity!r}"

    code, message = _error_code_and_message(lambda: cf.list_distributions_by_realtime_log_config())
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "Name or ARN must be provided.", f"unexpected message {message!r}"

    # the malformed request must not have perturbed the well-formed query.
    still_empty = cf.list_distributions_by_realtime_log_config(RealtimeLogConfigName=config_name)
    still_quantity = still_empty["DistributionList"]["Quantity"]
    assert still_quantity == 0, f"expected Quantity still 0 after the rejected call, got {still_quantity!r}"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_kinesis_stream(ctx) -> str:
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-cf-rtlog-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_stream(ctx, stream_name))

    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(5)
    raise AssertionError("Kinesis stream never reached ACTIVE status within timeout")


def _delete_stream(ctx, stream_name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_delivery_role(ctx, stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cf-rtlog-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-cf-rtlog-kinesis-put",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["kinesis:PutRecord", "kinesis:PutRecords"], "Resource": stream_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy(ctx, role_name))
    return role["Arn"]


def _delete_role_policy(ctx, role_name: str) -> None:
    try:
        ctx.client("iam").delete_role_policy(RoleName=role_name, PolicyName="sim2real-cf-rtlog-kinesis-put")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name: str) -> None:
    try:
        ctx.client("iam").delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_realtime_log_config(ctx) -> str:
    cf = ctx.client("cloudfront")
    stream_arn = _create_kinesis_stream(ctx)
    role_arn = _create_delivery_role(ctx, stream_arn)
    name = ctx.unique_name("sim2real-cf-rtlog-")

    # IAM roles are eventually consistent from CloudFront's perspective; retry briefly.
    deadline = time.monotonic() + 60.0
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cf.create_realtime_log_config(
                Name=name,
                EndPoints=[
                    {"StreamType": "Kinesis", "KinesisStreamConfig": {"RoleARN": role_arn, "StreamARN": stream_arn}}
                ],
                Fields=["timestamp", "c-ip"],
                SamplingRate=100,
            )
            break
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] in ("AccessDenied", "InvalidArgument"):
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"create_realtime_log_config never succeeded: {last_exc}")

    ctx.on_cleanup(lambda: _delete_realtime_log_config(ctx, name))
    return name


def _delete_realtime_log_config(ctx, name: str) -> None:
    try:
        ctx.client("cloudfront").delete_realtime_log_config(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchRealtimeLogConfig":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
