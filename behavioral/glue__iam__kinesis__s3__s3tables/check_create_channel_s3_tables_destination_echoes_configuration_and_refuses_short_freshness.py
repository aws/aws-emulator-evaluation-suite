"""create-channel-s3-tables-destination-echoes-configuration-and-refuses-short-freshness."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-s3-tables-destination-echoes-configuration-and-refuses-short-freshness"
GROUP = "state-machine"
SERVICES = ["glue", "iam", "kinesis", "s3", "s3tables"]

_ROLE_PROPAGATION_DEADLINE_S = 180.0
_DATA_FRESHNESS_S = 300
#: Documented data freshness range of a streaming table delivery, in seconds.
_FRESHNESS_MIN_S, _FRESHNESS_MAX_S = 300, 900
_FRESHNESS_OUT_OF_RANGE = (
    "ValidationException",
    f"DataFreshnessInSeconds must be between {_FRESHNESS_MIN_S} and {_FRESHNESS_MAX_S}.",
)
_PARTITION_SPEC = {"PartitionFields": [{"Transform": "TIME_HOUR", "SourceName": "creation_ts"}]}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel refuses a streaming-table delivery fresher than the documented 300 s minimum
    and creates no channel; at 300 s the channel goes ACTIVE, and DescribeChannel and ListChannels
    echo the table, partition spec, compression, schema, dead-letter bucket and freshness.

    Reference: https://docs.aws.amazon.com/streams/latest/dev/data-delivery-st-about.html
    """
    infra = _create_infra(ctx)

    bad_name = ctx.unique_name("sim2real-xsvc-stbl-bad-")
    got = _create_channel_error(ctx, infra, bad_name, _FRESHNESS_MIN_S - 1)
    assert got == _FRESHNESS_OUT_OF_RANGE, (
        f"DataFreshnessInSeconds={_FRESHNESS_MIN_S - 1} is below the documented minimum; expected "
        f"{_FRESHNESS_OUT_OF_RANGE!r}, got {got!r}"
    )
    names = {s["ChannelName"] for s in _list_channel_summaries(ctx, infra["stream_arn"])}
    assert bad_name not in names, f"the refused channel {bad_name!r} is listed: {names!r}"

    channel_name = ctx.unique_name("sim2real-xsvc-stbl-ch-")
    desc = _create_channel(ctx, infra, channel_name)
    channel_arn = desc["ChannelARN"]

    final = _wait_channel_status(ctx, channel_arn)
    assert final["ChannelStatus"] == "ACTIVE", (
        f"channel did not reach ACTIVE, status={final['ChannelStatus']!r} "
        f"reason={final.get('ChannelStatusReason')!r}"
    )
    dest = final["S3TablesDestinationConfiguration"]
    assert dest["DataFreshnessInSeconds"] == _DATA_FRESHNESS_S, (
        f"DescribeChannel echoes DataFreshnessInSeconds {dest['DataFreshnessInSeconds']!r}, "
        f"expected {_DATA_FRESHNESS_S}"
    )
    dlq = {k: dest["DeadLetterQueueS3Configuration"].get(k) for k in ("BucketARN", "ExpectedBucketOwner")}
    assert dlq == {"BucketARN": infra["dlq_bucket_arn"], "ExpectedBucketOwner": ctx.account}, (
        f"DescribeChannel echoes the dead-letter queue as {dlq!r}"
    )
    tables = dest["S3TablesConfigurationList"]
    assert len(tables) == 1, f"expected one streaming table configuration, got {tables!r}"
    table = {k: tables[0].get(k) for k in ("TableBucketARN", "Namespace", "TableName", "CompressionType", "PartitionSpec")}
    want = {
        "TableBucketARN": infra["table_bucket_arn"], "Namespace": infra["namespace"],
        "TableName": infra["table_name"], "CompressionType": "ZSTD", "PartitionSpec": _PARTITION_SPEC,
    }
    assert table == want, f"DescribeChannel echoes the table as {table!r}, expected {want!r}"
    streams = [
        (c["StreamARN"], c["RecordConfiguration"].get("RecordFormatType"), c["RecordConfiguration"].get("GSRSchemaARN"))
        for c in final["StreamConfigurationList"]
    ]
    assert streams == [(infra["stream_arn"], "JSON", infra["schema_arn"])], (
        f"DescribeChannel echoes the streams as {streams!r}"
    )

    summaries = {
        s["ChannelARN"]: s for s in _list_channel_summaries(ctx, infra["stream_arn"])
    }
    assert set(summaries) == {channel_arn}, f"ListChannels lists {sorted(summaries)!r}, expected only {channel_arn!r}"
    summary = summaries[channel_arn]
    assert summary["ChannelDestinationType"] == "S3_TABLES", (
        f"expected ChannelDestinationType=S3_TABLES, got {summary['ChannelDestinationType']!r}"
    )


def _create_channel_error(ctx, infra: dict, channel_name: str, freshness: int) -> tuple:
    """(code, message) of a CreateChannel refusal, past the role-propagation refusals."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + _ROLE_PROPAGATION_DEADLINE_S
    while True:
        try:
            resp = kinesis.create_channel(**_channel_request(ctx, infra, channel_name, freshness))
        except ClientError as exc:
            err = exc.response["Error"]
            role_not_yet_assumable = err["Code"] == "ValidationException" and "assume" in err.get(
                "Message", ""
            ).lower()
            if role_not_yet_assumable and time.monotonic() < deadline:
                time.sleep(5)
                continue
            return err["Code"], err.get("Message")
        arn = resp["ChannelDescription"]["ChannelARN"]
        ctx.on_cleanup(lambda: _delete_channel_and_wait_gone(ctx, arn))
        raise AssertionError(f"CreateChannel accepted {channel_name!r}: {resp['ChannelDescription']!r}")


def _channel_request(ctx, infra: dict, channel_name: str, freshness: int) -> dict:
    return {
        "ChannelName": channel_name,
        "ServiceExecutionRoleARN": infra["role_arn"],
        "StreamConfigurationList": [
            {
                "StreamARN": infra["stream_arn"],
                "RecordConfiguration": {
                    "RecordFormatType": "JSON",
                    "GSRSchemaARN": infra["schema_arn"],
                },
            }
        ],
        "S3TablesDestinationConfiguration": {
            "DataFreshnessInSeconds": freshness,
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
                    "PartitionSpec": _PARTITION_SPEC,
                }
            ],
        },
        "Tags": {"sim2real": "xsvc-stbl"},
    }


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
            resp = kinesis.create_channel(**_channel_request(ctx, infra, channel_name, _DATA_FRESHNESS_S))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
