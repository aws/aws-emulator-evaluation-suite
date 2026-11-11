"""sagemaker-feature-store-offline-store-missing-s3-permission-negative."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags

CHECK = "sagemaker-feature-store-offline-store-missing-s3-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """Revoking s3:PutObject from a feature group's role after creation blocks its offline store
    (Blocked with a reason, no new objects); restoring it returns the store to Active and new
    records land again, while a sibling group with full permissions keeps writing.
    """
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    fs_runtime = ctx.client("sagemaker-featurestore-runtime")

    bucket = _create_bucket(ctx)
    write_statements = [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket", "s3:DeleteObject", "s3:GetBucketAcl"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ]
    read_only_statements = [
        {
            "Effect": "Allow",
            "Action": ["s3:GetBucketAcl", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ]

    good_role = _create_role(ctx, write_statements)
    # CreateFeatureGroup synchronously probes S3 write access, so the target role starts with
    # write access and loses it only after creation.
    target_role = _create_role(ctx, write_statements)

    good_fg = _create_and_await_feature_group(ctx, sm, "sim2real-sm-fg-good-", bucket, "good-offline", good_role["arn"])
    target_fg = _create_and_await_feature_group(
        ctx, sm, "sim2real-sm-fg-target-", bucket, "target-offline", target_role["arn"]
    )

    _put_record(fs_runtime, good_fg, ctx.unique_name("sim2real-rec-good-"))
    _put_record(fs_runtime, target_fg, ctx.unique_name("sim2real-rec-pre-break-"))

    good_keys = _poll_until(
        ctx,
        lambda: _list_objects(s3, bucket, "good-offline"), lambda keys: len(keys) > 0, timeout_s=900, interval_s=2
    )
    assert good_keys
    pre_break_keys = _poll_until(
        ctx,
        lambda: _list_objects(s3, bucket, "target-offline"), lambda keys: len(keys) > 0, timeout_s=900, interval_s=2
    )
    assert pre_break_keys
    baseline_count = len(pre_break_keys)

    iam.put_role_policy(
        RoleName=target_role["name"],
        PolicyName=target_role["policy_name"],
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": read_only_statements}),
    )

    _put_record(fs_runtime, target_fg, ctx.unique_name("sim2real-rec-blocked-"))
    blocked_desc = _poll_until(
        ctx,
        lambda: sm.describe_feature_group(FeatureGroupName=target_fg),
        lambda d: d.get("OfflineStoreStatus", {}).get("Status") == "Blocked",
        timeout_s=600,
        interval_s=2,
    )
    assert blocked_desc["OfflineStoreStatus"]["Status"] == "Blocked"
    assert blocked_desc["OfflineStoreStatus"].get("BlockedReason")
    assert len(_list_objects(s3, bucket, "target-offline")) == baseline_count

    iam.put_role_policy(
        RoleName=target_role["name"],
        PolicyName=target_role["policy_name"],
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": write_statements}),
    )

    restored_desc = _poll_until(
        ctx,
        lambda: sm.describe_feature_group(FeatureGroupName=target_fg),
        lambda d: d.get("OfflineStoreStatus", {}).get("Status") == "Active",
        timeout_s=600,
        interval_s=2,
    )
    assert restored_desc["OfflineStoreStatus"]["Status"] == "Active"

    _put_record(fs_runtime, target_fg, ctx.unique_name("sim2real-rec-restored-"))
    restored_keys = _poll_until(
        ctx,
        lambda: _list_objects(s3, bucket, "target-offline"),
        lambda keys: len(keys) > baseline_count,
        timeout_s=900,
        interval_s=2,
    )
    assert len(restored_keys) > baseline_count


def _event_time() -> str:
    # PutRecord requires a String-typed EventTimeFeature to be ISO-8601, not a Unix epoch.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _put_record(fs_runtime: Any, feature_group_name: str, record_id: str) -> None:
    fs_runtime.put_record(
        FeatureGroupName=feature_group_name,
        Record=[
            {"FeatureName": "record_id", "ValueAsString": record_id},
            {"FeatureName": "event_time", "ValueAsString": _event_time()},
            {"FeatureName": "value", "ValueAsString": "1.0"},
        ],
    )


def _create_and_await_feature_group(
    ctx: Any, sm: Any, name_prefix: str, bucket: str, prefix: str, role_arn: str
) -> str:
    fg_name = ctx.unique_name(name_prefix)
    _create_feature_group_with_role_retry(
        sm,
        FeatureGroupName=fg_name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "String"},
            {"FeatureName": "value", "FeatureType": "Fractional"},
        ],
        OfflineStoreConfig={
            "S3StorageConfig": {"S3Uri": f"s3://{bucket}/{prefix}"},
            "DisableGlueTableCreation": True,
        },
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_feature_group(FeatureGroupName=fg_name))
    _poll_until(
        ctx,
        lambda: sm.describe_feature_group(FeatureGroupName=fg_name),
        lambda d: d["FeatureGroupStatus"] in ("Created", "CreateFailed"),
        timeout_s=180,
        interval_s=2,
    )
    desc = sm.describe_feature_group(FeatureGroupName=fg_name)
    assert desc["FeatureGroupStatus"] == "Created", f"{fg_name} failed to create: {desc}"
    return fg_name


def _list_objects(s3: Any, bucket: str, prefix: str) -> list[str]:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
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
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        contents = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if contents:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-sm-policy-")
    if policy_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return {"arn": role_arn, "name": role_name, "policy_name": policy_name}


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


def _create_feature_group_with_role_retry(
    sm: Any, *, timeout_s: float = 90.0, interval_s: float = 2.0, **kwargs: Any
) -> dict[str, Any]:
    """Retry CreateFeatureGroup while a just-created role propagates through IAM."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return sm.create_feature_group(**kwargs)
        except Exception as exc:  # noqa: BLE001
            if _error_code(exc) not in ("ValidationException", "AccessDeniedException"):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
