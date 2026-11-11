"""sagemaker-feature-store-offline-store-writes-to-s3."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-feature-store-offline-store-writes-to-s3"
GROUP = "event-propagation"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A record put into a feature group with an OfflineStoreConfig is asynchronously written to
    the configured S3 location as a non-empty parquet object containing that record_id.
    """
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    fs_runtime = ctx.client("sagemaker-featurestore-runtime")

    bucket = _create_bucket(ctx)
    role = _create_role(ctx, [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:DeleteObject",
                "s3:GetBucketAcl",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ])

    fg_name = ctx.unique_name("sim2real-sm-fg-")
    _create_feature_group_with_retry(
        sm,
        timeout_s=_budget_s(ctx, 120.0),
        ctx=ctx,
        FeatureGroupName=fg_name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "String"},
            {"FeatureName": "value", "FeatureType": "Fractional"},
        ],
        OfflineStoreConfig={
            "S3StorageConfig": {"S3Uri": f"s3://{bucket}/offline"},
            "DisableGlueTableCreation": True,
        },
        RoleArn=role["arn"],
        Tags=[{"Key": "sim2real", "Value": "offline-store-writes-to-s3"}],
    )
    ctx.on_cleanup(lambda: sm.delete_feature_group(FeatureGroupName=fg_name))

    _poll_until(
        ctx,
        lambda: sm.describe_feature_group(FeatureGroupName=fg_name),
        lambda d: d["FeatureGroupStatus"] in ("Created", "CreateFailed"),
        timeout_s=180,
        interval_s=2,
    )
    fg_desc = sm.describe_feature_group(FeatureGroupName=fg_name)
    assert fg_desc["FeatureGroupStatus"] == "Created", (
        f"expected FeatureGroupStatus Created, got {fg_desc['FeatureGroupStatus']!r}"
    )

    record_id = ctx.unique_name("sim2real-rec-")
    event_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fs_runtime.put_record(
        FeatureGroupName=fg_name,
        Record=[
            {"FeatureName": "record_id", "ValueAsString": record_id},
            {"FeatureName": "event_time", "ValueAsString": event_time},
            {"FeatureName": "value", "ValueAsString": "42.5"},
        ],
    )
    ctx.on_cleanup(lambda: fs_runtime.delete_record(
        FeatureGroupName=fg_name, RecordIdentifierValueAsString=record_id, EventTime=event_time,
    ))

    # SageMaker writes an empty marker .txt object under the prefix before the parquet data
    # lands, so poll for a non-empty object rather than any key.
    sizes = _poll_until(
        ctx,
        lambda: {k: s3.head_object(Bucket=bucket, Key=k)["ContentLength"] for k in _list_offline_objects(s3, bucket)},
        lambda sizes: any(sz > 0 for sz in sizes.values()),
        timeout_s=900,
        interval_s=2,
    )
    captured_keys = [k for k, sz in sizes.items() if sz > 0]
    total_size = sum(sizes[k] for k in captured_keys)
    assert captured_keys, (
        f"expected at least one non-empty object under s3://{bucket}/offline within 900s, "
        f"got only empty/no keys: {sorted(sizes)}"
    )
    assert total_size > 0, (
        f"expected non-empty offline-store object(s), got total_size=0 across {captured_keys}"
    )

    _assert_record_present(s3, bucket, captured_keys, record_id)


def _assert_record_present(s3, bucket: str, keys: list[str], record_id: str) -> None:
    import io as _io

    import pyarrow.parquet as pq
    for key in keys:
        if not key.endswith(".parquet"):
            continue
        data = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        table = pq.read_table(_io.BytesIO(data))
        ids = table.column("record_id").to_pylist() if "record_id" in table.column_names else []
        if record_id in ids:
            return
    raise AssertionError(f"record_id {record_id} not found in any offline-store parquet object among {keys!r}")


def _create_feature_group_with_retry(sm, *, timeout_s: float = 60.0, ctx=None, **kwargs: Any) -> None:
    """Retry CreateFeatureGroup while a just-created role and its inline policy propagate through
    IAM; an AccessDenied other than the role's own policy not yet allowing the action raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_feature_group(**kwargs)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            denied = "AccessDenied" in message or "not authorized" in message.lower()
            transient_role_propagation = (
                code == "ValidationException"
                and "role" in message.lower()
                and (not denied or "no identity-based policy allows" in message)
            )
            if transient_role_propagation and time.monotonic() < deadline:
                time.sleep(2)
                continue
            if transient_role_propagation and ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    "the role to propagate for CreateFeatureGroup: the run budget ended first; not graded"
                ) from e
            raise


def _list_offline_objects(s3, bucket: str) -> list[str]:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix="offline")
    return [o["Key"] for o in resp.get("Contents", [])]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, timeout_s: float = 600.0, interval_s: float = 2.0):
    """Poll probe() until predicate holds, within timeout_s and 5 s before the run's budget ends."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s:.0f}s; last value={last}")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-").lower()
    if ctx.region == "us-east-1":  # S3 CreateBucket rejects LocationConstraint only here (API quirk, not a region pin)
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "offline-store-writes-to-s3"}]}
    )

    def _cleanup() -> None:
        contents = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if contents:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_role(ctx: Any, policy_statements: list[dict[str, Any]]) -> dict[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "offline-store-writes-to-s3"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-sm-policy-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"arn": role_arn, "name": role_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
