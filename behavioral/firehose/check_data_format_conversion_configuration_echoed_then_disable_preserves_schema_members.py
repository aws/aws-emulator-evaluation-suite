"""data-format-conversion-configuration-echoed-then-disable-preserves-schema-members."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-format-conversion-configuration-echoed-then-disable-preserves-schema-members"
GROUP = "overly-permissive"
SERVICES = ["firehose"]

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _poll_until(probe, predicate, *, timeout_s=180, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last observed: {last!r}")


def _bucket_arn(name):
    return f"arn:aws:s3:::{name}"


def _make_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-dfc-bkt-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behavioral-check", "Value": CHECK}]}
    )

    def _teardown():
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_teardown)
    return name


def _delete_role(ctx, role_name):
    """Teardown: inline policies first, then the role; a failure RAISES."""
    iam = ctx.client("iam")
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _delivery_role_arn(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-dfc-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="firehose-destination-and-glue-access",
        PolicyDocument=json.dumps(
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
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "glue:GetDatabase",
                            "glue:GetTable",
                            "glue:GetTableVersion",
                            "glue:GetTableVersions",
                        ],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    return resp["Role"]["Arn"]


def _glue_name(ctx, kind):
    return ctx.unique_name(f"sim2real_behav_fh_dfc_{kind}_").replace("-", "_")


def _create_glue_table(ctx):
    glue = ctx.client("glue")
    db = _glue_name(ctx, "db")
    glue.create_database(DatabaseInput={"Name": db})
    ctx.on_cleanup(lambda: _try(lambda: glue.delete_database(Name=db)))
    table = _glue_name(ctx, "tbl")
    glue.create_table(
        DatabaseName=db,
        TableInput={
            "Name": table,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "parquet", "EXTERNAL": "TRUE"},
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "marker", "Type": "string"},
                    {"Name": "n", "Type": "int"},
                ],
                "Location": "s3://sim2real-placeholder/main/",
                "InputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": (
                        "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
                    )
                },
            },
        },
    )
    ctx.on_cleanup(lambda: _try(lambda: glue.delete_table(DatabaseName=db, Name=table)))
    return db, table


#: Error codes that mean a teardown step's resource is already gone.
_GONE = {"NoSuchEntity", "NoSuchBucket", "ResourceNotFoundException", "EntityNotFoundException"}


def _try(fn):
    """One teardown step: a resource already gone is done; any other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE:
            raise


def _delete_stream(ctx, name):
    _try(lambda: ctx.client("firehose").delete_delivery_stream(
        DeliveryStreamName=name, AllowForceDelete=True))


def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]


def _wait_active(ctx, name, timeout_s=180, interval_s=3):
    return _poll_until(
        lambda: _describe(ctx, name),
        lambda d: d["DeliveryStreamStatus"] == "ACTIVE",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"delivery stream {name} reaches ACTIVE",
    )


def _create_stream(ctx, name, dest_config):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 120
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration=dest_config,
                Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Describe echoes a DataFormatConversionConfiguration exactly, leaving unsupplied CatalogId
    and BlockSizeBytes absent; an update naming only Enabled=false flips Enabled and keeps every
    other member of the block.
    """
    bucket = _make_bucket(ctx)
    role_arn = _delivery_role_arn(ctx)
    database, table = _create_glue_table(ctx)
    name = ctx.unique_name("sim2real-behav-fh-dfc-stream-")

    _create_stream(
        ctx,
        name,
        {
            "RoleARN": role_arn,
            "BucketARN": _bucket_arn(bucket),
            "BufferingHints": {"SizeInMBs": 64, "IntervalInSeconds": 300},
            "CompressionFormat": "UNCOMPRESSED",
            "DataFormatConversionConfiguration": {
                "Enabled": True,
                "InputFormatConfiguration": {"Deserializer": {"OpenXJsonSerDe": {}}},
                "OutputFormatConfiguration": {
                    "Serializer": {
                        "ParquetSerDe": {"Compression": "GZIP", "WriterVersion": "V2"}
                    }
                },
                "SchemaConfiguration": {
                    "RoleARN": role_arn,
                    "DatabaseName": database,
                    "TableName": table,
                    "Region": ctx.region,
                },
            },
        },
    )
    desc = _wait_active(ctx, name)
    ext = desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    conversion = ext["DataFormatConversionConfiguration"]
    assert conversion["Enabled"] is True, conversion
    schema = conversion["SchemaConfiguration"]
    assert schema["RoleARN"] == role_arn, schema
    assert schema["DatabaseName"] == database, schema
    assert schema["TableName"] == table, schema
    assert schema["Region"] == ctx.region, schema
    assert schema.get("CatalogId") is None, (
        f"CatalogId was never supplied and must stay absent/null, not defaulted to the account "
        f"id: {schema!r}"
    )
    deser = conversion["InputFormatConfiguration"]["Deserializer"]
    assert deser.get("OpenXJsonSerDe") is not None, deser
    assert deser.get("HiveJsonSerDe") is None, (
        f"only OpenXJsonSerDe was configured; HiveJsonSerDe must stay absent: {deser!r}"
    )
    parquet = conversion["OutputFormatConfiguration"]["Serializer"]["ParquetSerDe"]
    assert parquet["Compression"] == "GZIP", parquet
    assert parquet["WriterVersion"] == "V2", parquet
    assert parquet.get("BlockSizeBytes") is None, (
        f"BlockSizeBytes was never supplied and must stay absent/null, not defaulted to 256 MiB: "
        f"{parquet!r}"
    )

    version_id = desc["VersionId"]
    destination_id = desc["Destinations"][0]["DestinationId"]
    ctx.client("firehose").update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId=version_id,
        DestinationId=destination_id,
        ExtendedS3DestinationUpdate={
            "DataFormatConversionConfiguration": {"Enabled": False}
        },
    )
    desc2 = _describe(ctx, name)
    ext2 = desc2["Destinations"][0]["ExtendedS3DestinationDescription"]
    conversion2 = ext2["DataFormatConversionConfiguration"]
    assert conversion2["Enabled"] is False, (
        f"Enabled must flip to False after the update: {conversion2!r}"
    )
    assert conversion2["SchemaConfiguration"]["DatabaseName"] == database, (
        f"an update naming only DataFormatConversionConfiguration.Enabled must PRESERVE the "
        f"stored SchemaConfiguration rather than wiping it, got "
        f"{conversion2.get('SchemaConfiguration')!r}"
    )
    assert conversion2["OutputFormatConfiguration"]["Serializer"].get("ParquetSerDe") is not None, (
        f"the ParquetSerDe serializer must survive an update that only disables conversion, got "
        f"{conversion2.get('OutputFormatConfiguration')!r}"
    )
    assert int(desc2["VersionId"]) == int(version_id) + 1, (
        f"a successful UpdateDestination must bump VersionId from {version_id!r}, got "
        f"{desc2['VersionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
