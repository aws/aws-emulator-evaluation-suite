"""create-channel-s3-tables-destination-creates-iceberg-table."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-s3-tables-destination-creates-iceberg-table"
GROUP = "state-machine"
SERVICES = ["glue", "iam", "kinesis", "s3", "s3tables"]

_ROLE_PROPAGATION_DEADLINE_S = 180.0
_TABLE_APPEARANCE_DEADLINE_S = 720.0
_PUT_RECORD_INTERVAL_S = 30.0


# timing:real-time — buffer: 300 s
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "plane:data", "dp:api",
      "timing:real-time")
def run(ctx) -> None:
    """Once records flow, a streaming-table channel creates its Iceberg table in S3 Tables, managed
    by kinesis.amazonaws.com.

    Reference: https://docs.aws.amazon.com/kinesis/data-delivery-st-create.html
    """
    infra = _create_infra(ctx)
    channel_name = ctx.unique_name("sim2real-xsvc-stbl-ch-")
    desc = _create_channel(ctx, infra, channel_name)
    channel_arn = desc["ChannelARN"]

    final = _wait_channel_status(ctx, channel_arn)
    assert final["ChannelStatus"] == "ACTIVE", (
        f"channel did not reach ACTIVE, status={final['ChannelStatus']!r} "
        f"reason={final.get('ChannelStatusReason')!r}"
    )
    s3tables_desc = final["S3TablesDestinationConfiguration"]["S3TablesConfigurationList"][0]
    assert s3tables_desc["TableBucketARN"] == infra["table_bucket_arn"], (
        f"expected TableBucketARN={infra['table_bucket_arn']!r}, got {s3tables_desc['TableBucketARN']!r}"
    )
    assert s3tables_desc["TableName"] == infra["table_name"], (
        f"expected TableName={infra['table_name']!r}, got {s3tables_desc['TableName']!r}"
    )

    summaries = {
        s["ChannelARN"]: s for s in _list_channel_summaries(ctx, infra["stream_arn"])
    }
    summary = summaries[channel_arn]
    assert summary["ChannelDestinationType"] == "S3_TABLES", (
        f"expected ChannelDestinationType=S3_TABLES, got {summary['ChannelDestinationType']!r}"
    )

    table = _wait_for_table(ctx, infra, channel_arn)
    assert table["name"] == infra["table_name"], f"expected table name {infra['table_name']!r}, got {table['name']!r}"
    assert table["namespace"] == [infra["namespace"]], (
        f"expected namespace [{infra['namespace']!r}], got {table['namespace']!r}"
    )
    assert table["managedByService"] == "kinesis.amazonaws.com", (
        f"expected managedByService=kinesis.amazonaws.com, got {table.get('managedByService')!r}"
    )

    listed = ctx.client("s3tables").list_tables(
        tableBucketARN=infra["table_bucket_arn"], namespace=infra["namespace"]
    )["tables"]
    listed_names = {t["name"] for t in listed}
    assert listed_names == {infra["table_name"]}, (
        f"expected ListTables to report only {infra['table_name']!r}, got {listed_names!r}"
    )


def _create_table_bucket_and_namespace(ctx, table_name: str) -> tuple[str, str]:
    s3tables = ctx.client("s3tables")
    bucket_name = ctx.unique_name("sim2real-xsvc-stbl-tb-")
    bucket = s3tables.create_table_bucket(name=bucket_name)
    bucket_arn = bucket["arn"]
    namespace = ctx.unique_name("sim2real_xsvc_stbl_ns_").replace("-", "_")

    def _delete_table_bucket() -> None:
        try:
            s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=table_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        try:
            s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)

    ctx.on_cleanup(_delete_table_bucket)
    s3tables.create_namespace(tableBucketARN=bucket_arn, namespace=[namespace])
    return bucket_arn, namespace


def _create_dlq_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-stbl-dlq-").lower()
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_s3_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "xsvc-stbl"}]}
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
    name = ctx.unique_name("sim2real-xsvc-stbl-strm-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "xsvc-stbl"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _create_gsr_schema(ctx) -> str:
    glue = ctx.client("glue")
    registry_name = ctx.unique_name("sim2real-xsvc-stbl-reg-")
    glue.create_registry(RegistryName=registry_name)
    ctx.on_cleanup(
        lambda: glue.delete_registry(RegistryId={"RegistryName": registry_name})
    )

    schema_name = ctx.unique_name("sim2real-xsvc-stbl-schema-")
    definition = json.dumps(
        {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "creation_ts": {"type": "string", "format": "date-time"},
                "value": {"type": "number"},
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
    role_name = ctx.unique_name("sim2real-xsvc-stbl-role-")
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
        Tags=[{"Key": "sim2real", "Value": "xsvc-stbl"}],
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
    table_name = ctx.unique_name("sim2real_xsvc_stbl_table_").replace("-", "_")
    table_bucket_arn, namespace = _create_table_bucket_and_namespace(ctx, table_name)
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
        "table_name": table_name,
    }


def _create_channel(ctx, infra: dict, channel_name: str) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + _ROLE_PROPAGATION_DEADLINE_S
    while True:
        try:
            resp = kinesis.create_channel(
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
                        {
                            "TableBucketARN": infra["table_bucket_arn"],
                            "Namespace": infra["namespace"],
                            "TableName": infra["table_name"],
                            "CompressionType": "ZSTD",
                            "PartitionSpec": {
                                "PartitionFields": [
                                    {"Transform": "TIME_HOUR", "SourceName": "creation_ts"}
                                ]
                            },
                        }
                    ],
                },
                Tags={"sim2real": "xsvc-stbl"},
            )
            channel_arn = resp["ChannelDescription"]["ChannelARN"]
            ctx.on_cleanup(lambda arn=channel_arn: _delete_channel_and_wait_gone(ctx, arn))
            return resp["ChannelDescription"]
        except ClientError as exc:
            err = exc.response["Error"]
            role_not_yet_assumable = err["Code"] == "ValidationException" and "assume" in err.get(
                "Message", ""
            ).lower()
            if role_not_yet_assumable and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


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


def _list_channel_summaries(ctx, stream_arn: str) -> list[dict]:
    kinesis = ctx.client("kinesis")
    summaries: list[dict] = []
    paginator = kinesis.get_paginator("list_channels")
    for page in paginator.paginate(StreamFilter=[{"StreamARN": stream_arn}]):
        summaries.extend(page["ChannelSummaries"])
    return summaries


def _put_probe_record(ctx, stream_name: str, record_id: str) -> None:
    kinesis = ctx.client("kinesis")
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    payload = json.dumps({"id": record_id, "creation_ts": now, "value": 1}).encode()
    kinesis.put_record(StreamName=stream_name, Data=payload, PartitionKey=record_id)


def _wait_for_table(ctx, infra: dict, channel_arn: str) -> dict:
    """Feeds records until the channel's Iceberg table appears, bounded by a deadline."""
    s3tables = ctx.client("s3tables")
    deadline = time.monotonic() + _TABLE_APPEARANCE_DEADLINE_S
    next_put = 0.0
    attempt = 0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            attempt += 1
            _put_probe_record(ctx, infra["stream_name"], f"probe-{attempt}")
            next_put = time.monotonic() + _PUT_RECORD_INTERVAL_S
        try:
            return s3tables.get_table(
                tableBucketARN=infra["table_bucket_arn"],
                namespace=infra["namespace"],
                name=infra["table_name"],
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
        time.sleep(5)
    raise AssertionError(
        f"channel {channel_arn} never created table {infra['table_name']!r} within "
        f"{_TABLE_APPEARANCE_DEADLINE_S}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
