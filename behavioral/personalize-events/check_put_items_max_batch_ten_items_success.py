"""put-items-max-batch-ten-items-success."""
from __future__ import annotations

import csv
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-items-max-batch-ten-items-success"
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

_PERSONALIZE_TAGS = [{"tagKey": "sim2real-check", "tagValue": CHECK}]
_IAM_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]
_S3_TAGS = {"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutItems accepts a batch of exactly 10 items (the documented maximum) on an ACTIVE Items dataset,
    and a dataset export (ingestionMode PUT) returns exactly those 10 itemIds with their prices."""
    dataset_group_arn = _create_dataset_group(ctx)
    dataset_arn = _create_dataset(ctx, dataset_group_arn)
    pe = ctx.client("personalize-events")
    items = [
        {"itemId": f"item-{i}", "properties": json.dumps({"price": float(i)})}
        for i in range(10)
    ]
    resp = pe.put_items(datasetArn=dataset_arn, items=items)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 from put_items, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    bucket = _create_export_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    personalize = ctx.client("personalize")
    prefix = "export"
    job_arn = _create_export_job_with_role_retry(
        personalize, ctx.unique_name("sim2real-pevt-exportjob-"), dataset_arn, bucket, prefix, role_arn,
    )
    job = _poll_until(
        lambda: personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)["datasetExportJob"],
        lambda j: j["status"] in ("ACTIVE", "CREATE FAILED"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    assert job["status"] == "ACTIVE", f"export job failed: {job.get('failureReason')}"

    rows = _read_exported_rows(ctx, bucket, prefix)
    by_id = {r["ITEM_ID"]: r for r in rows}
    expected_ids = {f"item-{i}" for i in range(10)}
    assert set(by_id) == expected_ids, (
        f"expected exactly the 10 itemIds this call put ({sorted(expected_ids)}), "
        f"got {sorted(by_id)}"
    )
    for i in range(10):
        got_price = float(by_id[f"item-{i}"]["PRICE"])
        assert got_price == float(i), (
            f"item-{i}: expected exported price {float(i)!r}, got {got_price!r}"
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
    arn = personalize.create_dataset_group(name=name, tags=_PERSONALIZE_TAGS)["datasetGroupArn"]
    ctx.on_cleanup(lambda: personalize.delete_dataset_group(datasetGroupArn=arn))
    _poll_until(
        lambda: personalize.describe_dataset_group(datasetGroupArn=arn)["datasetGroup"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    return arn


def _create_dataset(ctx, dataset_group_arn):
    personalize = ctx.client("personalize")
    schema = {
        "type": "record",
        "name": "Items",
        "namespace": "com.amazonaws.personalize.schema",
        "fields": _ITEMS_FIELDS,
        "version": "1.0",
    }
    schema_arn = personalize.create_schema(
        name=ctx.unique_name("sim2real-pevt-schema-items-"), schema=json.dumps(schema)
    )["schemaArn"]
    ctx.on_cleanup(lambda: personalize.delete_schema(schemaArn=schema_arn))
    dataset_arn = personalize.create_dataset(
        name=ctx.unique_name("sim2real-pevt-ds-items-"),
        datasetGroupArn=dataset_group_arn,
        datasetType="Items",
        schemaArn=schema_arn,
        tags=_PERSONALIZE_TAGS,
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
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this is an S3 API quirk, not a hardcoded target region (ctx.region drives the bucket).
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging=_S3_TAGS)

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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY), Tags=_IAM_TAGS
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

    _poll_until(lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"], lambda a: bool(a), timeout_s=30.0, interval_s=3.0)
    return role_arn


def _create_export_job_with_role_retry(
    personalize, job_name, dataset_arn, bucket, prefix, role_arn, timeout_s=1200.0, interval_s=20.0
):
    """Two independent asynchronous delays can make this call 400 right after a successful
    PutItems: IAM role/trust-policy propagation to personalize.amazonaws.com, and Personalize's
    own ingested-data visibility for PUT-mode export ("No data found in datasets for
    ingestionMode: PUT ... wait up to 15 minutes"). Retry the call that surfaces both, bounded
    by a deadline."""
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
                tags=_PERSONALIZE_TAGS,
            )["datasetExportJobArn"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"create_dataset_export_job did not succeed for role {role_arn} / dataset {dataset_arn} "
        f"within {timeout_s}s: {last_exc}"
    )


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
