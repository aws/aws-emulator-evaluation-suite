"""put-users-success."""
from __future__ import annotations

import csv
import io
import json
import time

from behavioral_harness import tags

CHECK = "put-users-success"
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutUsers persists the user in the Users dataset: a PUT-mode CreateDatasetExportJob to S3 (the
    only independent read path) exports exactly one row for this user carrying the submitted
    properties."""
    dataset_group_arn = _create_dataset_group(ctx)
    dataset_arn = _create_dataset(
        ctx, dataset_group_arn, "Users", "Users", _USERS_FIELDS, "users"
    )
    pe = ctx.client("personalize-events")
    user_id = ctx.unique_name("user-")
    resp = pe.put_users(
        datasetArn=dataset_arn,
        users=[{"userId": user_id, "properties": json.dumps({"age": 34})}],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert set(resp.keys()) == {"ResponseMetadata"}

    bucket = _create_export_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    personalize = ctx.client("personalize")
    # 1200s: AWS documents "up to 15 minutes" for a fresh PUT write to become visible to
    # CreateDatasetExportJob; this is that bound plus margin.
    matching = _await_exported_row(ctx, personalize, dataset_arn, bucket, role_arn, user_id, time.monotonic() + 1200.0)
    assert len(matching) == 1, f"expected exactly one exported row for {user_id!r}, got {matching}"
    assert matching[0]["AGE"] == "34", f"expected AGE=34 for {user_id!r}, got {matching[0]}"


# ===== helpers =====
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


_TRANSIENT_EXPORT_REJECTIONS = (
    # IAM role/policy not yet effective for personalize.amazonaws.com: an export right after
    # put_role_policy/put_bucket_policy can get InvalidInputException "Insufficient privileges for
    # writing data in S3" for a role whose policy is correct.
    "assume",
    "insufficient privileges",
    # PutUsers/PutItems/PutActions ingestion into the exportable dataset store lags the API call:
    # AWS answers "No data found in datasets for ingestionMode: PUT. If you have recently imported
    # the data, please wait up to 15 minutes before trying to Export".
    "no data found in datasets",
)


def _create_export_job_with_retry(personalize, deadline, **kwargs):
    """Retries CreateDatasetExportJob itself -- the point where the service both evaluates the role
    and checks the dataset has exportable data -- on the two transient rejections real AWS is known
    to give right after a write. A genuinely broken role or a
    genuinely absent write still fails, just after *deadline*."""
    while True:
        try:
            return personalize.create_dataset_export_job(**kwargs)["datasetExportJobArn"]
        except personalize.exceptions.InvalidInputException as exc:
            message = str(exc).lower()
            if not any(m in message for m in _TRANSIENT_EXPORT_REJECTIONS) or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _await_exported_row(ctx, personalize, dataset_arn, bucket, role_arn, user_id, deadline):
    """Runs the full create-export-job -> poll -> read cycle, repeating it while the row this
    check just wrote is absent. The dataset-level "no data found" gate can clear
    (an earlier run's rows already made the dataset exportable) while THIS row -- written seconds
    ago -- has its own, separate visibility lag and is not yet in that export. A single export
    attempt cannot tell "never landed" from "hasn't propagated yet"; only repeating across the
    same deadline that bounds the create-job retry can."""
    attempt = 0
    while True:
        attempt += 1
        prefix = f"export-{attempt}"
        job_arn = _create_export_job_with_retry(
            personalize,
            deadline,
            jobName=ctx.unique_name("sim2real-pevt-exportjob-"),
            datasetArn=dataset_arn,
            jobOutput={"s3DataDestination": {"path": f"s3://{bucket}/{prefix}/"}},
            roleArn=role_arn,
            ingestionMode="PUT",
        )
        _poll_until(
            lambda: personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)["datasetExportJob"],
            lambda j: j["status"] in ("ACTIVE", "CREATE FAILED"),
            timeout_s=1200.0,
            interval_s=2.0,
        )
        job = personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)["datasetExportJob"]
        assert job["status"] == "ACTIVE", f"export job failed: {job.get('failureReason')}"
        rows = _read_exported_rows(ctx, bucket, prefix)
        matching = [r for r in rows if r["USER_ID"] == user_id]
        if matching:
            return matching
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no exported row for {user_id!r} within the ingestion-visibility budget "
                f"(last export had {len(rows)} unrelated row(s))"
            )
        time.sleep(2.0)  # each export cycle itself takes minutes on AWS


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
