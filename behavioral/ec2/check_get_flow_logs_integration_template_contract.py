"""op-contract-get-flow-logs-integration-template."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-flow-logs-integration-template"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetFlowLogsIntegrationTemplate succeeds for a real flow log, DryRun passes for a nonexistent
    id, and a real call for that id is rejected InvalidFlowLogId.NotFound with its exact message."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    log_bucket = ctx.unique_name("sim2real-behav-flowlog-src-")
    _create_bucket(ctx, log_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, log_bucket))

    flow_log_id = ec2.create_flow_logs(
        ResourceIds=[vpc_id],
        ResourceType="VPC",
        TrafficType="ALL",
        LogDestinationType="s3",
        LogDestination=f"arn:aws:s3:::{log_bucket}",
    )["FlowLogIds"][0]
    ctx.on_cleanup(lambda: ec2.delete_flow_logs(FlowLogIds=[flow_log_id]))

    _poll_until(
        lambda: ec2.describe_flow_logs(FlowLogIds=[flow_log_id])["FlowLogs"][0]["FlowLogStatus"],
        lambda status: status == "ACTIVE",
        timeout_s=60,
    )

    bucket = ctx.unique_name("sim2real-behav-flowlogs-")
    _create_bucket(ctx, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    integrate_service = {
        "AthenaIntegrations": [
            {
                "IntegrationResultS3DestinationArn": f"arn:aws:s3:::{bucket}/results/",
                "PartitionLoadFrequency": "daily",
            }
        ]
    }
    dest_arn = f"arn:aws:s3:::{bucket}/templates/"
    bogus_flow_log_id = "fl-00000000000000000"

    # Positive control: the rejection below is then attributable to the nonexistent id.
    real_result = _must_succeed(
        lambda: ec2.get_flow_logs_integration_template(
            FlowLogId=flow_log_id,
            ConfigDeliveryS3DestinationArn=dest_arn,
            IntegrateServices=integrate_service,
        )
    )
    assert flow_log_id in real_result["Result"], (
        f"expected the real flow log id in the generated template, got {real_result!r}"
    )

    # DryRun validates request shape and permissions without checking the flow log exists.
    dry_run_code, dry_run_message = _error(
        lambda: ec2.get_flow_logs_integration_template(
            FlowLogId=bogus_flow_log_id,
            ConfigDeliveryS3DestinationArn=dest_arn,
            IntegrateServices=integrate_service,
            DryRun=True,
        )
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == _DRY_RUN_MESSAGE, (
        f"expected DryRun message {_DRY_RUN_MESSAGE!r}, got {dry_run_message!r}"
    )

    code, message = _error(
        lambda: ec2.get_flow_logs_integration_template(
            FlowLogId=bogus_flow_log_id,
            ConfigDeliveryS3DestinationArn=dest_arn,
            IntegrateServices=integrate_service,
        )
    )
    assert code == "InvalidFlowLogId.NotFound", (
        f"expected InvalidFlowLogId.NotFound, got {code!r}"
    )
    expected = f"Flow Log Id Not Found or Not Active.{bogus_flow_log_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    kwargs = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint for itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


def _must_succeed(fn):
    """Call fn(); return its result, turning a ClientError into an assertion failure."""
    try:
        return fn()
    except ClientError as exc:
        raise AssertionError(
            f"expected the positive control to succeed, but it raised {exc.response.get('Error', {})!r}"
        ) from exc


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
