"""flow-logs-integration-template-parameterized-by-config."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "flow-logs-integration-template-parameterized-by-config"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetFlowLogsIntegrationTemplate's generated CloudFormation template is
    parameterized with the actual S3 destinations supplied in the request --
    it is not a static/canned template."""
    ec2 = ctx.client("ec2")
    ctx.client("s3")

    vpc_id = ec2.create_vpc(CidrBlock="10.77.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-flowlog-vpc-")}])

    log_bucket = ctx.unique_name("sim2real-flowlog-src-")
    config_bucket = ctx.unique_name("sim2real-flowlog-cfg-")
    athena_bucket = ctx.unique_name("sim2real-flowlog-athena-")
    for bucket in (log_bucket, config_bucket, athena_bucket):
        _create_bucket(ctx, bucket)
        ctx.on_cleanup(lambda b=bucket: _empty_and_delete_bucket(ctx, b))

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

    config_arn = f"arn:aws:s3:::{config_bucket}/templates"
    athena_result_arn = f"arn:aws:s3:::{athena_bucket}/results"
    integrate_services = {
        "AthenaIntegrations": [
            {
                "IntegrationResultS3DestinationArn": athena_result_arn,
                "PartitionLoadFrequency": "daily",
            }
        ]
    }
    result = ec2.get_flow_logs_integration_template(
        FlowLogId=flow_log_id,
        ConfigDeliveryS3DestinationArn=config_arn,
        IntegrateServices=integrate_services,
    )["Result"]

    # The template must be parameterized with exactly what we supplied to
    # THIS call, not a generic/canned template.
    assert flow_log_id in result, f"expected FlowLogId {flow_log_id!r} embedded in template, got: {result!r}"
    assert config_bucket in result, (
        f"expected config bucket {config_bucket!r} embedded in template, got: {result!r}"
    )

    # Differential check: swapping the config-delivery destination for a
    # different bucket must change the generated template's parameterization
    # -- proving it isn't a static/canned response keyed only on FlowLogId.
    other_config_bucket = ctx.unique_name("sim2real-flowlog-cfg2-")
    _create_bucket(ctx, other_config_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, other_config_bucket))
    other_config_arn = f"arn:aws:s3:::{other_config_bucket}/templates"
    other_result = ec2.get_flow_logs_integration_template(
        FlowLogId=flow_log_id,
        ConfigDeliveryS3DestinationArn=other_config_arn,
        IntegrateServices=integrate_services,
    )["Result"]
    assert other_config_bucket in other_result, (
        f"expected new config bucket {other_config_bucket!r} embedded in second template, "
        f"got: {other_result!r}"
    )
    assert other_config_bucket not in result, (
        f"first template must not contain the second call's bucket {other_config_bucket!r}"
    )
    assert config_bucket not in other_result, (
        f"second template must not contain the first call's bucket {config_bucket!r}"
    )
    assert result != other_result, (
        "templates from two calls with different S3 destinations must differ -- "
        f"got identical result: {result!r}"
    )


def _create_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    kwargs = {"Bucket": bucket_name}
    # us-east-1 is S3's API default region: CreateBucket rejects an explicit
    # LocationConstraint naming it, so the literal here is the S3 wire contract,
    # not an assumption about which region this check runs in (ctx.region).
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "flow-logs-integration-template-parameterized-by-config"}]})


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


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
