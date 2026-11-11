"""put-users-max-batch-ten-users-success."""
from __future__ import annotations

import csv
import io
import json
import time

from behavioral_harness import tags

CHECK = "put-users-max-batch-ten-users-success"
GROUP = "data-plane"
SERVICES = ["personalize-events"]

_USERS_FIELDS = [
    {"name": "USER_ID", "type": "string"},
    {"name": "AGE", "type": ["null", "int"]},
]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "personalize.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutUsers accepts a batch of exactly 10 users (the documented maximum) on an ACTIVE Users dataset,
    and a dataset export (ingestionMode PUT) shows exactly those 10 userIds with their AGE values."""
    dataset_group_arn = _create_dataset_group(ctx)
    dataset_arn = _create_dataset(
        ctx, dataset_group_arn, "Users", "Users", _USERS_FIELDS, "users"
    )
    pe = ctx.client("personalize-events")
    prefix = ctx.unique_name("sim2real-pevt-maxbatch10-")
    user_ids = [f"{prefix}{i}" for i in range(10)]
    users = [
        {"userId": uid, "properties": json.dumps({"age": 20 + i})}
        for i, uid in enumerate(user_ids)
    ]
    resp = pe.put_users(datasetArn=dataset_arn, users=users)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    bucket = _create_export_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    personalize = ctx.client("personalize")
    export_prefix = "export"
    job_arn = _create_export_job_with_propagation_retry(
        personalize,
        job_name=ctx.unique_name("sim2real-pevt-exportjob-"),
        dataset_arn=dataset_arn,
        bucket=bucket,
        export_prefix=export_prefix,
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

    rows = _read_exported_rows(ctx, bucket, export_prefix)
    exported = {r["USER_ID"]: r["AGE"] for r in rows if r["USER_ID"] in user_ids}
    assert len(exported) == 10, (
        f"expected all 10 submitted users to land, got {sorted(exported)} of {user_ids}"
    )
    for i, uid in enumerate(user_ids):
        assert exported[uid] == str(20 + i), (
            f"user {uid}: expected exported AGE {20 + i}, got {exported[uid]!r}"
        )


_EXPORT_JOB_RETRYABLE_MESSAGES = (
    # Role/bucket-policy propagation: CreateDatasetExportJob validates S3 write access
    # SYNCHRONOUSLY at call time, so a just-created role can transiently fail this check.
    "Insufficient privileges",
    # PUT-mode ingestion propagation: personalize-events writes land in a streaming store
    # that is periodically compacted into the export-visible snapshot; AWS's own message
    # documents "wait up to 15 minutes" after a recent PutUsers/PutItems/PutEvents call.
    "No data found in datasets for ingestionMode",
)


def _create_export_job_with_propagation_retry(
    personalize, job_name, dataset_arn, bucket, export_prefix, role_arn,
    timeout_s=960.0, interval_s=30.0,
):
    """CreateDatasetExportJob validates both the role's S3 write access AND the presence of
    exportable PUT-mode data SYNCHRONOUSLY at call time -- not later, during the job's own
    async lifecycle -- so a role that has not propagated, or data that has not yet been
    compacted into the export-visible snapshot, surfaces as an immediate InvalidInputException
    that a poll on the job's status can never see. Retries only those specific, named
    conditions within a bounded deadline; anything else about the request being wrong is
    raised immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return personalize.create_dataset_export_job(
                jobName=job_name,
                datasetArn=dataset_arn,
                jobOutput={"s3DataDestination": {"path": f"s3://{bucket}/{export_prefix}/"}},
                roleArn=role_arn,
                ingestionMode="PUT",
            )["datasetExportJobArn"]
        except personalize.exceptions.InvalidInputException as e:
            retryable = any(m in str(e) for m in _EXPORT_JOB_RETRYABLE_MESSAGES)
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_export_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-pevt-export-").lower().replace("_", "-")[:63].strip("-")
    if ctx.region == "us-east-1":
        # S3 API quirk, not a region assumption: us-east-1 rejects an explicit
        # LocationConstraint on CreateBucket, every other region requires one.
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

    _poll_until(lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"], lambda a: bool(a), timeout_s=30.0, interval_s=3.0)
    return role_arn


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
