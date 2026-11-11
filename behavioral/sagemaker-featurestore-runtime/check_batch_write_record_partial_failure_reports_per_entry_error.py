"""batch-write-record-partial-failure-reports-per-entry-error."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-write-record-partial-failure-reports-per-entry-error"
GROUP = "batch-operations"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchWriteRecord with one entry for a real feature group and one for a nonexistent one writes
    the valid entry and reports exactly one per-entry error, ValidationError with the exact message,
    for the invalid one rather than failing the whole batch."""
    fg_name = _create_online_feature_group(ctx)
    bogus_fg = ctx.unique_name("sim2real-fsr-nofg-")
    t0 = time.time()

    fsr = ctx.client("sagemaker-featurestore-runtime")
    resp = fsr.batch_write_record(
        Entries=[
            {
                "FeatureGroupName": fg_name,
                "Record": [
                    {"FeatureName": "record_id", "ValueAsString": "rec-partial"},
                    {"FeatureName": "event_time", "ValueAsString": str(t0)},
                    {"FeatureName": "feature_a", "ValueAsString": "valid-entry"},
                ],
            },
            {
                "FeatureGroupName": bogus_fg,
                "Record": [
                    {"FeatureName": "record_id", "ValueAsString": "rec-bad"},
                    {"FeatureName": "event_time", "ValueAsString": str(t0)},
                    {"FeatureName": "feature_a", "ValueAsString": "invalid-entry"},
                ],
            },
        ]
    )

    errors = resp["Errors"]
    matching = [e for e in errors if e["Entry"]["FeatureGroupName"] == bogus_fg]
    assert len(matching) == 1, f"expected exactly one error for the bogus feature group, got {errors}"
    assert matching[0]["ErrorCode"] == "ValidationError", f"expected ValidationError, got {matching[0]['ErrorCode']!r}"
    expected = (
        f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name "
        f"[arn:aws:sagemaker:{ctx.region}:{ctx.account}:feature-group/{bogus_fg}]."
    )
    got = matching[0].get("ErrorMessage")
    assert got == expected, f"expected ErrorMessage {expected!r}, got {got!r}"

    def probe():
        return _get_record_dict(ctx, fg_name, "rec-partial")

    valid_record = _poll_until(probe, lambda r: r is not None, timeout_s=30.0)
    assert valid_record["feature_a"] == "valid-entry", (
        f"expected the valid entry's feature_a to be written despite the sibling entry's "
        f"failure, got {valid_record!r}"
    )


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_feature_group(ctx, name))
    _wait_for_feature_group_status(ctx, name, "Created")
    return name


def _get_record_dict(ctx, fg_name, record_id, **kwargs):
    fsr = ctx.client("sagemaker-featurestore-runtime")
    resp = fsr.get_record(FeatureGroupName=fg_name, RecordIdentifierValueAsString=record_id, **kwargs)
    record = resp.get("Record")
    if record is None:
        return None
    return {fv["FeatureName"]: fv.get("ValueAsString") for fv in record}


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
