"""put-items-success."""
from __future__ import annotations

import csv
import io
import json
import time

from behavioral_harness import tags

CHECK = "put-items-success"
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
    """PutItems writes one item with metadata into an ACTIVE Items dataset (HTTP 200, empty body), and a
    dataset export shows exactly one row for that item with price 9.99."""
    dataset_group_arn = _create_dataset_group(ctx)
    dataset_arn = _create_dataset(
        ctx, dataset_group_arn, "Items", "Items", _ITEMS_FIELDS, "items"
    )
    pe = ctx.client("personalize-events")
    item_id = ctx.unique_name("item-")
    resp = pe.put_items(
        datasetArn=dataset_arn,
        items=[{"itemId": item_id, "properties": json.dumps({"price": 9.99})}],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected HTTP 200 from PutItems, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert set(resp.keys()) == {"ResponseMetadata"}, (
        f"expected PutItems response to carry no data fields, got keys {set(resp.keys())}"
    )

    bucket = _create_export_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    personalize = ctx.client("personalize")
    matching, rows_seen = _export_until_item_appears(
        ctx, personalize, dataset_arn, bucket, role_arn, item_id
    )
    assert matching, (
        f"item {item_id!r} (PutItems returned HTTP 200 for it) never appeared in a "
        f"CreateDatasetExportJob read-back of the Items dataset; last export had "
        f"{rows_seen} row(s), none matching"
    )
    assert len(matching) == 1, (
        f"expected exactly one exported row for {item_id!r}, got {matching}"
    )
    got_price = float(matching[0]["PRICE"])
    assert abs(got_price - 9.99) < 1e-6, (
        f"expected exported PRICE 9.99 for {item_id!r}, got {got_price!r}"
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


_SHARED_DSG_NAME = "sim2real-pevt-dsg-shared"


def _find_arn(list_fn, items_key, name, arn_key, **kwargs):
    next_token = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["nextToken"] = next_token
        resp = list_fn(**call_kwargs)
        for item in resp.get(items_key, []):
            if item.get("name") == name:
                return item[arn_key]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _find_dataset_group_arn(personalize):
    """Adopts ANY existing ACTIVE dataset group this suite created (name prefix
    "sim2real-pevt-dsg") rather than insisting on one exact name -- a prior run's group that
    didn't get torn down (e.g. an interrupted suite) is reused instead of minting a new one and
    blowing the account's hard 5-active-dataset-group quota."""
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = personalize.list_dataset_groups(**kwargs)
        for g in resp.get("datasetGroups", []):
            if g["name"].startswith("sim2real-pevt-dsg") and g["status"] == "ACTIVE":
                return g["datasetGroupArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_dataset_group(ctx):
    """Finds-or-creates the ONE shared custom dataset group reused by the whole suite (a
    custom dataset group holds one dataset of each type -- Interactions, Items, Users, Actions,
    Action_Interactions -- so every check fits in it), instead of each check minting its own,
    which blows the account's 5-active-dataset-group quota under a full-suite run. Never
    deleted by an individual check; it is shared by the suite's checks."""
    personalize = ctx.client("personalize")
    arn = _find_dataset_group_arn(personalize)
    if arn is None:
        try:
            arn = personalize.create_dataset_group(name=_SHARED_DSG_NAME)["datasetGroupArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_dataset_group_arn(personalize)
    _poll_until(
        lambda: personalize.describe_dataset_group(datasetGroupArn=arn)["datasetGroup"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    return arn


def _find_dataset_arn_by_type(personalize, dataset_group_arn, dataset_type):
    next_token = None
    while True:
        kwargs = {"datasetGroupArn": dataset_group_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = personalize.list_datasets(**kwargs)
        for ds in resp.get("datasets", []):
            if ds.get("datasetType") == dataset_type and ds.get("status") == "ACTIVE":
                return ds["datasetArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_dataset(ctx, dataset_group_arn, dataset_type, record_name, fields, name_prefix):
    """Finds-or-creates the shared <dataset_type> dataset (and its schema) inside the shared
    dataset group. Adopts ANY existing ACTIVE dataset of this TYPE in the group (not just by
    name) -- a custom dataset group allows only one dataset per type, so a stray same-typed
    dataset left over from a prior run is reused rather than fighting it for the slot. Never
    deleted by an individual check; it is shared by the suite's checks."""
    personalize = ctx.client("personalize")
    arn = _find_dataset_arn_by_type(personalize, dataset_group_arn, dataset_type)
    if arn is None:
        ds_name = f"sim2real-pevt-ds-shared-{name_prefix}"
        schema_name = f"sim2real-pevt-schema-shared-{name_prefix}"
        schema_arn = _find_arn(personalize.list_schemas, "schemas", schema_name, "schemaArn")
        if schema_arn is None:
            schema = {
                "type": "record",
                "name": record_name,
                "namespace": "com.amazonaws.personalize.schema",
                "fields": fields,
                "version": "1.0",
            }
            try:
                schema_arn = personalize.create_schema(
                    name=schema_name, schema=json.dumps(schema)
                )["schemaArn"]
            except personalize.exceptions.ResourceAlreadyExistsException:
                schema_arn = _find_arn(personalize.list_schemas, "schemas", schema_name, "schemaArn")
        try:
            arn = personalize.create_dataset(
                name=ds_name,
                datasetGroupArn=dataset_group_arn,
                datasetType=dataset_type,
                schemaArn=schema_arn,
            )["datasetArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_arn(
                personalize.list_datasets, "datasets", ds_name, "datasetArn",
                datasetGroupArn=dataset_group_arn,
            )
    _poll_until(
        lambda: personalize.describe_dataset(datasetArn=arn)["dataset"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=300.0,
        interval_s=10.0,
    )
    return arn


def _create_export_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-pevt-export-").lower().replace("_", "-")[:63].strip("-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "s3-export-access"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
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
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    _poll_until(lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"], lambda a: bool(a), timeout_s=30.0, interval_s=3.0)
    return role_arn


_ROLE_NOT_READY_MARKERS = (
    "cannot be assumed",
    "is not authorized",
    "Insufficient privileges for writing data in S3",
)


def _create_export_job_with_retry(personalize, timeout_s=180.0, interval_s=10.0, **kwargs):
    """personalize.amazonaws.com needs the freshly created role's trust policy and the S3
    bucket policy to propagate before it can assume the role and use it; retries the ACTUAL
    create call on that specific failure instead of guessing a fixed sleep, so the wait ends
    the moment the role really becomes usable."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return personalize.create_dataset_export_job(**kwargs)["datasetExportJobArn"]
        except personalize.exceptions.ClientError as exc:
            reason = str(exc)
            if not any(marker in reason for marker in _ROLE_NOT_READY_MARKERS):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"create_dataset_export_job kept rejecting the export role within {timeout_s}s "
        f"(role/trust/bucket-policy propagation never completed): {last_exc}"
    )


def _export_until_item_appears(
    ctx, personalize, dataset_arn, bucket, role_arn, item_id, timeout_s=900.0, interval_s=30.0
):
    """A single PutItems write is not guaranteed to be reflected in the very next
    CreateDatasetExportJob snapshot -- incremental ingestion into the Items dataset lags the
    API call that accepted it. Re-exports (each one a fresh job/prefix, since a job's output is
    a point-in-time snapshot that does not update after the fact) until the item shows up or
    the bound is exhausted."""
    deadline = time.monotonic() + timeout_s
    attempt = 0
    last_rows = []
    while time.monotonic() < deadline:
        attempt += 1
        prefix = f"export-{attempt}"
        job_arn = _create_export_job_with_retry(
            personalize,
            jobName=ctx.unique_name("sim2real-pevt-exportjob-"),
            datasetArn=dataset_arn,
            jobOutput={"s3DataDestination": {"path": f"s3://{bucket}/{prefix}/"}},
            roleArn=role_arn,
            ingestionMode="PUT",
        )
        _poll_until(
            lambda: personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)[
                "datasetExportJob"
            ],
            lambda j: j["status"] in ("ACTIVE", "CREATE FAILED"),
            timeout_s=1200.0,
            interval_s=15.0,
        )
        job = personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)[
            "datasetExportJob"
        ]
        assert job["status"] == "ACTIVE", f"export job failed: {job.get('failureReason')}"
        last_rows = _read_exported_rows(ctx, bucket, prefix)
        matching = [r for r in last_rows if r["ITEM_ID"] == item_id]
        if matching:
            return matching, len(last_rows)
        time.sleep(interval_s)
    return [], len(last_rows)


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
