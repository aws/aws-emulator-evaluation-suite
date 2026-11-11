"""put-items-property-update-reflected-in-export."""
from __future__ import annotations

import csv
import io
import json
import time

from behavioral_harness import tags

CHECK = "put-items-property-update-reflected-in-export"
GROUP = "data-plane"
SERVICES = ["personalize-events"]

_ITEMS_FIELDS = [
    {"name": "ITEM_ID", "type": "string"},
    {"name": "PRICE", "type": ["null", "float"]},
]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "personalize.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second PutItems for the same itemId with a new price replaces the first: a dataset export
    (ingestionMode PUT) shows exactly one row for the item, with PRICE 20.0."""
    dataset_group_arn = _create_dataset_group(ctx)
    dataset_arn = _create_dataset(
        ctx, dataset_group_arn, "Items", "Items", _ITEMS_FIELDS, "items"
    )
    pe = ctx.client("personalize-events")
    item_id = "upsert-item"
    pe.put_items(datasetArn=dataset_arn, items=[{"itemId": item_id, "properties": json.dumps({"price": 10.0})}])
    pe.put_items(datasetArn=dataset_arn, items=[{"itemId": item_id, "properties": json.dumps({"price": 20.0})}])

    bucket = _create_export_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    personalize = ctx.client("personalize")
    prefix = "export"
    job_arn = _create_export_job_when_data_visible(
        personalize,
        job_name=ctx.unique_name("sim2real-pevt-exportjob-"),
        dataset_arn=dataset_arn,
        bucket=bucket,
        prefix=prefix,
        role_arn=role_arn,
    )
    _poll_until(
        lambda: personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)["datasetExportJob"],
        lambda j: j["status"] in ("ACTIVE", "CREATE FAILED"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    job = personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)["datasetExportJob"]
    assert job["status"] == "ACTIVE", f"export job failed: {job.get('failureReason')}"

    rows = _read_exported_rows(ctx, bucket, prefix)
    matching = [r for r in rows if r["ITEM_ID"] == item_id]
    assert len(matching) == 1, f"expected exactly one exported row for {item_id!r}, got {matching}"
    assert matching[0]["PRICE"] == "20.0", (
        f"expected the latest PutItems value (20.0) reflected in the export, got {matching[0]['PRICE']!r}"
    )


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_dataset_group(ctx):
    personalize = ctx.client("personalize")
    name = ctx.unique_name("sim2real-pevt-dsg-")
    arn = personalize.create_dataset_group(name=name)["datasetGroupArn"]
    ctx.on_cleanup(lambda: personalize.delete_dataset_group(datasetGroupArn=arn))
    _poll_until(
        lambda: personalize.describe_dataset_group(datasetGroupArn=arn)["datasetGroup"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    return arn


def _create_dataset(ctx, dataset_group_arn, dataset_type, record_name, fields, name_prefix):
    personalize = ctx.client("personalize")
    schema = {
        "type": "record",
        "name": record_name,
        "namespace": "com.amazonaws.personalize.schema",
        "fields": fields,
        "version": "1.0",
    }
    schema_arn = personalize.create_schema(
        name=ctx.unique_name(f"sim2real-pevt-schema-{name_prefix}-"), schema=json.dumps(schema)
    )["schemaArn"]
    ctx.on_cleanup(lambda: personalize.delete_schema(schemaArn=schema_arn))
    dataset_arn = personalize.create_dataset(
        name=ctx.unique_name(f"sim2real-pevt-ds-{name_prefix}-"),
        datasetGroupArn=dataset_group_arn,
        datasetType=dataset_type,
        schemaArn=schema_arn,
    )["datasetArn"]
    ctx.on_cleanup(lambda: personalize.delete_dataset(datasetArn=dataset_arn))
    _poll_until(
        lambda: personalize.describe_dataset(datasetArn=dataset_arn)["dataset"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )
    return dataset_arn


def _create_export_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-pevt-export-").lower().replace("_", "-")[:63].strip("-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    def _empty_and_delete():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)
    return bucket


def _create_export_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pevt-exp-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "s3-export-access"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    s3 = ctx.client("s3")
    bucket_policy = {
        "Version": "2012-10-17",
        "Id": "PersonalizeS3BucketAccessPolicy",
        "Statement": [
            {
                "Sid": "PersonalizeS3BucketAccessPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "personalize.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))
    return role_arn


def _create_export_job_when_data_visible(
    personalize, job_name, dataset_arn, bucket, prefix, role_arn, timeout_s=1000.0, interval_s=30.0
):
    """CreateDatasetExportJob(ingestionMode=PUT) rejects with InvalidInputException ("No data
    found in datasets for ingestionMode: PUT ... wait up to 15 minutes before trying to Export")
    until incrementally-PutItems data becomes visible to the export path; poll the create call
    itself (the observable condition, per AWS's own error text) rather than sleeping blindly."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return personalize.create_dataset_export_job(
                jobName=job_name,
                datasetArn=dataset_arn,
                jobOutput={"s3DataDestination": {"path": f"s3://{bucket}/{prefix}/"}},
                roleArn=role_arn,
                ingestionMode="PUT",
            )["datasetExportJobArn"]
        except Exception as exc:  # noqa: BLE001 - broad on purpose, retried below
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"CreateDatasetExportJob kept failing within {timeout_s}s: {last_exc}")


def _read_exported_rows(ctx, bucket, prefix):
    s3 = ctx.client("s3")
    keys = [
        o["Key"]
        for o in s3.list_objects_v2(Bucket=bucket, Prefix=f"{prefix}/").get("Contents", [])
        if not o["Key"].endswith("/")
    ]
    assert keys, f"export job produced no objects under s3://{bucket}/{prefix}/"
    rows = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read().decode("utf-8")
        rows.extend(list(csv.DictReader(io.StringIO(body))))
    return rows


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
