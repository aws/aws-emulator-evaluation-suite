"""put-events-minimal-fields-success."""
from __future__ import annotations

import csv
import io
import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "put-events-minimal-fields-success"
GROUP = "data-plane"
SERVICES = ["personalize-events"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "personalize.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutEvents with only trackingId, sessionId and an event of eventType, sentAt and itemId (no
    userId) answers HTTP 200 with an empty body, and an Interactions dataset export shows exactly one
    row with that eventType."""
    dataset_group_arn = _create_dataset_group(ctx)
    dataset_arn = _create_interactions_dataset(ctx, dataset_group_arn)
    tracking_id = _create_event_tracker(ctx, dataset_group_arn)
    pe = ctx.client("personalize-events")
    event_type = ctx.unique_name("sim2real-pevt-min-")
    resp = pe.put_events(
        trackingId=tracking_id,
        sessionId=ctx.unique_name("sim2real-pevt-sess-"),
        eventList=[
            {
                "eventType": event_type,
                "sentAt": datetime.now(timezone.utc),
                "itemId": ctx.unique_name("sim2real-pevt-min-item-"),
            }
        ],
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected HTTP 200 from PutEvents, got {resp['ResponseMetadata']}"
    )
    assert set(resp.keys()) == {"ResponseMetadata"}, (
        f"expected an empty PutEvents body, got keys {set(resp.keys())}"
    )

    personalize = ctx.client("personalize")
    bucket = _create_export_bucket(ctx)
    role_arn = _create_export_role(ctx, bucket)
    matching, all_rows = _poll_until(
        lambda: _export_and_find(ctx, personalize, dataset_arn, bucket, role_arn, event_type),
        lambda result: len(result[0]) >= 1,
        timeout_s=1200.0,
        interval_s=45.0,
    )
    assert len(matching) == 1, (
        f"expected exactly one exported Interactions row with event_type={event_type!r}, "
        f"got {len(matching)} (export had {len(all_rows)} PUT-ingested rows total)"
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


_SHARED_DSG_NAME = "sim2real-pevt-min-dsg-shared"
_SHARED_TRACKER_NAME = "sim2real-pevt-min-trk-shared"


def _find_dataset_group_arn(personalize):
    """Adopts ANY existing ACTIVE dataset group this check created (name prefix
    "sim2real-pevt-min-dsg") rather than insisting on one exact name -- a prior run's group that
    didn't get torn down (e.g. an interrupted suite) is reused instead of minting a new one and
    blowing the account's hard 5-active-dataset-group quota. Deliberately its OWN dataset group,
    not the "sim2real-pevt-dsg-shared" one the rest of the personalize-events suite adopts: that
    group's Interactions dataset slot can stay taken after a delete (delete_dataset finalization
    outlives even a generous poll, so a same-group create under any new name keeps reporting
    ResourceAlreadyExistsException)."""
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = personalize.list_dataset_groups(**kwargs)
        for g in resp.get("datasetGroups", []):
            if g["name"].startswith("sim2real-pevt-min-dsg") and g["status"] == "ACTIVE":
                return g["datasetGroupArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_dataset_group(ctx):
    """Finds-or-creates the ONE dataset group this check reuses across re-runs. Never deleted
    individually; it is shared by the suite's checks."""
    personalize = ctx.client("personalize")
    arn = _find_dataset_group_arn(personalize)
    if arn is None:
        try:
            arn = personalize.create_dataset_group(
                name=_SHARED_DSG_NAME,
                tags=[{"tagKey": "sim2real-suite", "tagValue": "personalize-events"}],
            )["datasetGroupArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_dataset_group_arn(personalize)
    _poll_until(
        lambda: personalize.describe_dataset_group(datasetGroupArn=arn)["datasetGroup"]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=180.0,
        interval_s=5.0,
    )
    return arn


def _find_first_arn(list_fn, items_key, arn_key, **kwargs):
    next_token = None
    while True:
        call_kwargs = dict(kwargs)
        if next_token:
            call_kwargs["nextToken"] = next_token
        resp = list_fn(**call_kwargs)
        for item in resp.get(items_key, []):
            if item.get("status") == "ACTIVE":
                return item[arn_key]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_event_tracker(ctx, dataset_group_arn):
    """Finds-or-creates the ONE event tracker for this check's dataset group. Adopts ANY
    existing ACTIVE tracker (not just by exact name) since a dataset group can only ever have
    one Interactions dataset/tracker anyway. Never deleted individually; it is shared by the suite's checks."""
    personalize = ctx.client("personalize")
    arn = _find_first_arn(
        personalize.list_event_trackers, "eventTrackers", "eventTrackerArn",
        datasetGroupArn=dataset_group_arn,
    )
    if arn is None:
        try:
            arn = personalize.create_event_tracker(
                name=_SHARED_TRACKER_NAME,
                datasetGroupArn=dataset_group_arn,
                tags=[{"tagKey": "sim2real-suite", "tagValue": "personalize-events"}],
            )["eventTrackerArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            arn = _find_first_arn(
                personalize.list_event_trackers, "eventTrackers", "eventTrackerArn",
                datasetGroupArn=dataset_group_arn,
            )
    tracker = _poll_until(
        lambda: personalize.describe_event_tracker(eventTrackerArn=arn)["eventTracker"],
        lambda t: t["status"] == "ACTIVE",
        timeout_s=120.0,
        interval_s=5.0,
    )
    return tracker["trackingId"]


def _find_interactions_dataset_arn(personalize, dataset_group_arn):
    next_token = None
    while True:
        kwargs = {"datasetGroupArn": dataset_group_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = personalize.list_datasets(**kwargs)
        for d in resp.get("datasets", []):
            if d["datasetType"] == "INTERACTIONS":
                return d["datasetArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


_SHARED_INTERACTIONS_SCHEMA_NAME = "sim2real-pevt-min-schema-interactions-shared"
_SHARED_INTERACTIONS_DATASET_NAME = "sim2real-pevt-min-ds-interactions-shared"

_INTERACTIONS_SCHEMA = {
    "type": "record",
    "name": "Interactions",
    "namespace": "com.amazonaws.personalize.schema",
    "fields": [
        {"name": "USER_ID", "type": "string"},
        {"name": "ITEM_ID", "type": "string"},
        {"name": "TIMESTAMP", "type": "long"},
        {"name": "EVENT_TYPE", "type": "string"},
    ],
    "version": "1.0",
}


def _find_schema_arn(personalize, name):
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = personalize.list_schemas(**kwargs)
        for s in resp.get("schemas", []):
            if s["name"] == name:
                return s["schemaArn"]
        next_token = resp.get("nextToken")
        if not next_token:
            return None


def _create_or_adopt_interactions_dataset(personalize, dataset_group_arn, schema_arn):
    try:
        return personalize.create_dataset(
            name=_SHARED_INTERACTIONS_DATASET_NAME,
            datasetGroupArn=dataset_group_arn,
            datasetType="Interactions",
            schemaArn=schema_arn,
            tags=[{"tagKey": "sim2real-suite", "tagValue": "personalize-events"}],
        )["datasetArn"]
    except personalize.exceptions.ResourceAlreadyExistsException:
        # The name can briefly still read as taken while a recently deleted same-named dataset
        # is still finalizing deletion -- the
        # lookup and the create-conflict can disagree for a few seconds; retry both together.
        return _find_interactions_dataset_arn(personalize, dataset_group_arn)


def _create_interactions_dataset(ctx, dataset_group_arn):
    """CreateEventTracker requires an Interactions dataset to already exist in the dataset
    group -- AWS raises ResourceNotFoundException ("Missing
    INTERACTIONS dataset with datasetgroup: ...") rather than creating one implicitly. Finds-or-
    creates the ONE shared Interactions dataset, same convention as the shared dataset group and
    tracker above: never deleted by an individual check.
    Real AWS rejects a nullable USER_ID/ITEM_ID at CreateSchema time (InvalidInputException,
    "USER_ID field cannot be of type null"), so both are plain "string" here -- whether an event
    that omits them at the PutEvents level still lands in an export is exactly what this check's
    terminal read settles."""
    personalize = ctx.client("personalize")
    arn = _find_interactions_dataset_arn(personalize, dataset_group_arn)
    if arn is not None:
        _poll_until(
            lambda: personalize.describe_dataset(datasetArn=arn)["dataset"]["status"],
            lambda s: s == "ACTIVE",
            timeout_s=300.0,
            interval_s=10.0,
        )
        return arn
    schema_arn = _find_schema_arn(personalize, _SHARED_INTERACTIONS_SCHEMA_NAME)
    if schema_arn is None:
        try:
            schema_arn = personalize.create_schema(
                name=_SHARED_INTERACTIONS_SCHEMA_NAME, schema=json.dumps(_INTERACTIONS_SCHEMA)
            )["schemaArn"]
        except personalize.exceptions.ResourceAlreadyExistsException:
            schema_arn = _find_schema_arn(personalize, _SHARED_INTERACTIONS_SCHEMA_NAME)
    arn = _poll_until(
        lambda: _create_or_adopt_interactions_dataset(
            personalize, dataset_group_arn, schema_arn
        ),
        lambda a: a is not None,
        timeout_s=120.0,
        interval_s=10.0,
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
    bucket = ctx.unique_name("sim2real-pevt-min-export-").lower().replace("_", "-")[:63].strip("-")
    if ctx.region == "us-east-1":
        # S3 CreateBucket quirk, not a region pin: us-east-1 rejects an explicit
        # LocationConstraint, every other region requires one.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
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
    role_name = ctx.unique_name("sim2real-pevt-min-exp-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _export_and_find(ctx, personalize, dataset_arn, bucket, role_arn, event_type):
    """Exports the Interactions dataset, restricted to ingestionMode=PUT (real-time PutEvents
    records only, not any bulk-imported rows), to an independent S3 destination this check owns
    -- the terminal read at the destination that PutEvents itself has no reader for. PutEvents'
    200 is not a durability guarantee: real AWS was observed exporting zero rows for an event
    just accepted, so the caller retries this whole export until the row appears or a bounded
    window elapses."""
    prefix = ctx.unique_name("export-")
    _run_export_job_with_role_propagation_retry(ctx, personalize, dataset_arn, bucket, role_arn, prefix)
    rows = _read_exported_rows(ctx, bucket, prefix)
    # A PUT-ingestion-mode export uses the raw real-time event record's own lowercase snake_case
    # columns ("event_type", "item_id", "session_id", ...), not the
    # Interactions dataset schema's declared UPPERCASE field names -- those govern a different,
    # BULK-ingestion-mode export.
    return [r for r in rows if r.get("event_type") == event_type], rows


def _looks_like_role_propagation_lag(reason):
    return any(
        token in reason.lower() for token in ("role", "not authorized", "access denied", "assume", "privilege")
    )


def _run_export_job_with_role_propagation_retry(ctx, personalize, dataset_arn, bucket, role_arn, prefix):
    """A role IAM already reports as created, and whose bucket policy already reports as set,
    can still be unusable by another AWS service for a longer eventual-consistency window than
    expected, up to several minutes. It can surface
    synchronously, as an immediate InvalidInputException naming insufficient S3 privileges from
    CreateDatasetExportJob itself, or asynchronously, as a CREATE FAILED naming the role. Retry
    on either signal, bounded to 5 minutes; any other failure reason raises immediately."""
    deadline = time.monotonic() + 300.0
    attempt = 0
    while True:
        attempt += 1
        try:
            job_arn = personalize.create_dataset_export_job(
                jobName=ctx.unique_name("sim2real-pevt-min-exportjob-"),
                datasetArn=dataset_arn,
                ingestionMode="PUT",
                jobOutput={"s3DataDestination": {"path": f"s3://{bucket}/{prefix}/"}},
                roleArn=role_arn,
                tags=[{"tagKey": "sim2real-check", "tagValue": CHECK}],
            )["datasetExportJobArn"]
        except personalize.exceptions.InvalidInputException as e:
            reason = str(e)
            if not _looks_like_role_propagation_lag(reason) or time.monotonic() > deadline:
                raise
            time.sleep(5.0)
            continue
        job = _poll_until(
            lambda: personalize.describe_dataset_export_job(datasetExportJobArn=job_arn)["datasetExportJob"],
            lambda j: j["status"] in ("ACTIVE", "CREATE FAILED"),
            timeout_s=1200.0,
            interval_s=15.0,
        )
        if job["status"] == "ACTIVE":
            return
        reason = (job.get("failureReason") or "")
        if not _looks_like_role_propagation_lag(reason) or time.monotonic() > deadline:
            raise AssertionError(f"dataset export job failed (attempt {attempt}): {reason}")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
