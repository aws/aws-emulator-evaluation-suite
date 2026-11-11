"""create-channel-s3-tables-without-partition-spec-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-s3-tables-without-partition-spec-rejected"
GROUP = "negative-classes"
SERVICES = ["glue", "iam", "kinesis", "s3", "s3tables"]

_ROLE_PROPAGATION_DEADLINE_S = 180.0
_PARTITION_SPEC_MISSING = ("ValidationException", "PartitionSpec is required.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel to a streaming table with no PartitionSpec is rejected; a spec'd one succeeds.

    Reference: https://docs.aws.amazon.com/kinesis/data-delivery-st-create.html
    """
    infra = _create_infra(ctx)

    bad_channel_name = ctx.unique_name("sim2real-xsvc-pspec-bad-")
    got_code, got_message = _create_channel_expect_error(ctx, infra, bad_channel_name, partition_spec=None)
    code, message = _PARTITION_SPEC_MISSING
    assert got_code == code, f"expected code {code!r}, got {got_code!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"

    after_reject = _list_channel_names(ctx, infra["stream_arn"])
    assert after_reject == set(), f"the rejected attempt left a channel behind: {after_reject!r}"

    good_channel_name = ctx.unique_name("sim2real-xsvc-pspec-ok-")
    desc = _create_channel(
        ctx,
        infra,
        good_channel_name,
        partition_spec={"PartitionFields": [{"Transform": "TIME_HOUR", "SourceName": "creation_ts"}]},
    )
    final = _wait_channel_status(ctx, desc["ChannelARN"])
    assert final["ChannelStatus"] == "ACTIVE", (
        f"spec'd channel did not reach ACTIVE, status={final['ChannelStatus']!r} "
        f"reason={final.get('ChannelStatusReason')!r}"
    )

    final_names = _list_channel_names(ctx, infra["stream_arn"])
    assert final_names == {good_channel_name}, (
        f"expected only {good_channel_name!r} on this stream, got {final_names!r}"
    )


def _create_table_bucket_and_namespace(ctx) -> tuple[str, str]:
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-xsvc-pspec-tb-")
    bucket = s3tables.create_table_bucket(name=bucket_name)
    bucket_arn = bucket["arn"]
    namespace = ctx.unique_name("sim2real_xsvc_pspec_ns_").replace("-", "_")

    def _cleanup() -> None:
        try:
            tables = s3tables.list_tables(tableBucketARN=bucket_arn, namespace=namespace)["tables"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        else:
            for table in tables:
                s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=table["name"])
            s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)

    ctx.on_cleanup(_cleanup)
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    return bucket_arn, namespace


def _create_dlq_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-pspec-dlq-").lower()
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_s3_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "xsvc-pspec"}]}
    )
    return f"arn:aws:s3:::{name}"


def _delete_s3_bucket(s3, name: str) -> None:
    objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
    if objs:
        s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _create_source_stream(ctx) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-xsvc-pspec-strm-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "xsvc-pspec"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _create_gsr_schema(ctx) -> str:
    glue = ctx.client("glue")
    registry_name = ctx.unique_name("sim2real-xsvc-pspec-reg-")
    glue.create_registry(RegistryName=registry_name)
    ctx.on_cleanup(lambda: glue.delete_registry(RegistryId={"RegistryName": registry_name}))

    schema_name = ctx.unique_name("sim2real-xsvc-pspec-schema-")
    definition = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "creation_ts": {"type": "string", "format": "date-time"},
            },
            "required": ["id", "creation_ts"],
        }
    )
    schema = glue.create_schema(
        RegistryId={"RegistryName": registry_name},
        SchemaName=schema_name,
        DataFormat="JSON",
        Compatibility="NONE",
        SchemaDefinition=definition,
    )
    schema_arn = schema["SchemaArn"]
    ctx.on_cleanup(lambda: glue.delete_schema(SchemaId={"SchemaArn": schema_arn}))
    return schema_arn


def _create_delivery_role(ctx, dlq_bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-pspec-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "kinesis.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": ctx.account},
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:kinesis:{ctx.region}:{ctx.account}:channel/*"
                        },
                    },
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "xsvc-pspec"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "delivery-policy"
    perms = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S3Tables",
                    "Effect": "Allow",
                    "Action": ["s3tables:*"],
                    "Resource": "*",
                },
                {
                    "Sid": "DlqBucket",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket", "s3:PutObject"],
                    "Resource": [dlq_bucket_arn, f"{dlq_bucket_arn}/*"],
                },
                {
                    "Sid": "Glue",
                    "Effect": "Allow",
                    "Action": ["glue:GetSchemaVersion", "glue:GetSchemaByDefinition"],
                    "Resource": "*",
                },
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=perms)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_infra(ctx) -> dict:
    table_bucket_arn, namespace = _create_table_bucket_and_namespace(ctx)
    dlq_bucket_arn = _create_dlq_bucket(ctx)
    stream_name, stream_arn = _create_source_stream(ctx)
    schema_arn = _create_gsr_schema(ctx)
    role_arn = _create_delivery_role(ctx, dlq_bucket_arn)
    return {
        "table_bucket_arn": table_bucket_arn,
        "namespace": namespace,
        "dlq_bucket_arn": dlq_bucket_arn,
        "stream_name": stream_name,
        "stream_arn": stream_arn,
        "schema_arn": schema_arn,
        "role_arn": role_arn,
    }


def _table_config(infra: dict, table_name: str, partition_spec: dict | None) -> dict:
    config = {
        "TableBucketARN": infra["table_bucket_arn"],
        "Namespace": infra["namespace"],
        "TableName": table_name,
        "CompressionType": "ZSTD",
    }
    if partition_spec is not None:
        config["PartitionSpec"] = partition_spec
    return config


def _call_create_channel(ctx, infra: dict, channel_name: str, partition_spec: dict | None):
    kinesis = ctx.client("kinesis")
    table_name = channel_name.replace("-", "_") + "_table"
    deadline = time.monotonic() + _ROLE_PROPAGATION_DEADLINE_S
    while True:
        try:
            return kinesis.create_channel(
                ChannelName=channel_name,
                ServiceExecutionRoleARN=infra["role_arn"],
                StreamConfigurationList=[
                    {
                        "StreamARN": infra["stream_arn"],
                        "RecordConfiguration": {
                            "RecordFormatType": "JSON",
                            "GSRSchemaARN": infra["schema_arn"],
                        },
                    }
                ],
                S3TablesDestinationConfiguration={
                    "DataFreshnessInSeconds": 300,
                    "DeadLetterQueueS3Configuration": {
                        "BucketARN": infra["dlq_bucket_arn"],
                        "ExpectedBucketOwner": ctx.account,
                    },
                    "S3TablesConfigurationList": [
                        _table_config(infra, table_name, partition_spec)
                    ],
                },
                Tags={"sim2real": "xsvc-pspec"},
            )
        except ClientError as exc:
            err = exc.response["Error"]
            role_not_yet_assumable = err["Code"] == "ValidationException" and "assume" in err.get(
                "Message", ""
            ).lower()
            if role_not_yet_assumable and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_channel_expect_error(
    ctx, infra: dict, channel_name: str, partition_spec: dict | None
) -> tuple[str, str]:
    try:
        resp = _call_create_channel(ctx, infra, channel_name, partition_spec)
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    channel_arn = resp["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _delete_channel_and_wait_gone(ctx, channel_arn))
    raise AssertionError(
        f"CreateChannel with no PartitionSpec unexpectedly succeeded: {channel_arn!r}"
    )


def _create_channel(ctx, infra: dict, channel_name: str, partition_spec: dict) -> dict:
    resp = _call_create_channel(ctx, infra, channel_name, partition_spec)
    channel_arn = resp["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _delete_channel_and_wait_gone(ctx, channel_arn))
    return resp["ChannelDescription"]


_TRANSITIONAL_CHANNEL_STATUSES = ("CREATING", "UPDATING")


def _delete_channel_and_wait_gone(ctx, channel_arn: str, timeout_s: float = 180.0) -> None:
    """DeleteChannel, then wait until DescribeChannel reports it gone.

    A refused delete is retried only while the channel reads CREATING or UPDATING; a channel
    already DELETING skips straight to the wait."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kinesis.delete_channel(ChannelARN=channel_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ResourceInUseException", "InvalidArgumentException"):
                raise
            status = _channel_status(kinesis, channel_arn)
            if status is None:
                return
            if status == "DELETING":
                break
            if status not in _TRANSITIONAL_CHANNEL_STATUSES or time.monotonic() > deadline:
                raise
            time.sleep(5)
    while time.monotonic() < deadline:
        if _channel_status(kinesis, channel_arn) is None:
            return
        time.sleep(5)
    raise AssertionError(f"channel {channel_arn} still describable {timeout_s}s after delete")


def _channel_status(kinesis, channel_arn: str) -> str | None:
    """The channel's ChannelStatus, or None once DescribeChannel reports it not found."""
    try:
        return kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]["ChannelStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _wait_channel_status(ctx, channel_arn: str, timeout_s: float = 240.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
        if desc["ChannelStatus"] in ("ACTIVE", "FAILED"):
            return desc
        time.sleep(5)
    raise AssertionError(f"channel {channel_arn} did not settle within {timeout_s}s")


def _list_channel_names(ctx, stream_arn: str) -> set[str]:
    kinesis = ctx.client("kinesis")
    names: set[str] = set()
    paginator = kinesis.get_paginator("list_channels")
    for page in paginator.paginate(StreamFilter=[{"StreamARN": stream_arn}]):
        for summary in page["ChannelSummaries"]:
            names.add(summary["ChannelName"])
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
