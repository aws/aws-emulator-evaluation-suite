"""batch-get-record-too-many-identifiers-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-record-too-many-identifiers-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetRecord with more than 100 Identifiers fails with ValidationException and the exact
    message, while the same call within the limit returns the stored record."""
    fg_name = _create_online_feature_group(ctx)
    t0 = time.time()
    _put_record(ctx, fg_name, "rec-batch", t0, {"feature_a": "present"})

    fsr = ctx.client("sagemaker-featurestore-runtime")

    too_many = [
        {"FeatureGroupName": fg_name, "RecordIdentifiersValueAsString": [f"id-{i}"]} for i in range(101)
    ]
    code, message = _error(lambda: fsr.batch_get_record(Identifiers=too_many))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    listed = ", ".join(
        f"BatchGetRecordIdentifier(featureGroupName={fg_name}, recordIdentifiersValueAsString=[id-{i}], featureNames=null)"
        for i in range(101)
    )
    expected = (
        f"1 validation error detected: Value '[{listed}]' at 'identifiers' failed to satisfy "
        f"constraint: Member must have length less than or equal to 100"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    def probe():
        return fsr.batch_get_record(
            Identifiers=[{"FeatureGroupName": fg_name, "RecordIdentifiersValueAsString": ["rec-batch"]}]
        )["Records"]

    records = _poll_until(probe, lambda recs: len(recs) == 1, timeout_s=30.0)
    got = records[0]["RecordIdentifierValueAsString"]
    assert got == "rec-batch", f"expected in-limit BatchGetRecord to still succeed and return rec-batch, got {got!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_feature_group_status(ctx, name, target_status, timeout_s=300.0, interval_s=5.0):
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = sm.describe_feature_group(FeatureGroupName=name)
        last = desc.get("FeatureGroupStatus")
        if last == target_status:
            return desc
        if last in ("CreateFailed", "DeleteFailed"):
            raise AssertionError(f"feature group {name} entered {last}: {desc.get('FailureReason')}")
        time.sleep(interval_s)
    raise AssertionError(f"feature group {name} did not reach {target_status} within {timeout_s}s (last={last})")


def _safe_delete_feature_group(ctx, name):
    try:
        ctx.client("sagemaker").delete_feature_group(FeatureGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _create_online_feature_group(ctx, extra_features=None, ttl_duration=None):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-fsr-")
    feature_defs = [
        {"FeatureName": "record_id", "FeatureType": "String"},
        {"FeatureName": "event_time", "FeatureType": "Fractional"},
    ] + (
        extra_features
        or [
            {"FeatureName": "feature_a", "FeatureType": "String"},
            {"FeatureName": "feature_b", "FeatureType": "String"},
            {"FeatureName": "feature_c", "FeatureType": "String"},
        ]
    )
    online_store_config = {"EnableOnlineStore": True}
    if ttl_duration is not None:
        online_store_config["TtlDuration"] = ttl_duration
    sm.create_feature_group(
        FeatureGroupName=name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=feature_defs,
        OnlineStoreConfig=online_store_config,
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_feature_group(ctx, name))
    _wait_for_feature_group_status(ctx, name, "Created")
    return name


def _put_record(ctx, fg_name, record_id, event_time, features, ttl_duration=None):
    fsr = ctx.client("sagemaker-featurestore-runtime")
    record = [
        {"FeatureName": "record_id", "ValueAsString": record_id},
        {"FeatureName": "event_time", "ValueAsString": str(event_time)},
    ] + [{"FeatureName": k, "ValueAsString": v} for k, v in features.items()]
    kwargs = {"FeatureGroupName": fg_name, "Record": record}
    if ttl_duration is not None:
        kwargs["TtlDuration"] = ttl_duration
    fsr.put_record(**kwargs)


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
