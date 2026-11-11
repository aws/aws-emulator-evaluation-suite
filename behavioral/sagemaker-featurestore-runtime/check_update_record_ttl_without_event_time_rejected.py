"""update-record-ttl-without-event-time-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-record-ttl-without-event-time-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateRecord rejects a TtlDuration supplied without an accompanying EventTime with
    ValidationError, leaving the record untouched; supplying both together succeeds."""
    fg_name = _create_online_feature_group(ctx)
    t0 = time.time()
    _put_record(ctx, fg_name, "rec-ttlreq", t0, {"feature_a": "original"})

    fsr = ctx.client("sagemaker-featurestore-runtime")

    def probe_initial():
        return _get_record_dict(ctx, fg_name, "rec-ttlreq")

    _poll_until(probe_initial, lambda r: r is not None, timeout_s=30.0)

    code, message = _error(
        lambda: fsr.update_record(
            FeatureGroupName=fg_name,
            RecordIdentifierValueAsString="rec-ttlreq",
            Features=[{"FeatureName": "feature_a", "ValueAsString": "should-not-apply"}],
            TtlDuration={"Unit": "Hours", "Value": 1},
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = (
        "Validation Error: EventTime is required when TtlDuration is specified or when the feature "
        "group has a default TTL configured. Include the EventTime feature in the Features list."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = _get_record_dict(ctx, fg_name, "rec-ttlreq")
    assert unchanged["feature_a"] == "original", (
        f"rejected UpdateRecord must not apply; expected feature_a='original', got {unchanged['feature_a']!r}"
    )

    # positive control: TtlDuration together with EventTime (conveyed via the
    # feature group's EventTimeFeatureName entry in Features) is accepted
    fsr.update_record(
        FeatureGroupName=fg_name,
        RecordIdentifierValueAsString="rec-ttlreq",
        Features=[
            {"FeatureName": "event_time", "ValueAsString": str(t0 + 10)},
            {"FeatureName": "feature_a", "ValueAsString": "updated-with-ttl"},
        ],
        TtlDuration={"Unit": "Hours", "Value": 1},
    )

    def probe_updated():
        return _get_record_dict(ctx, fg_name, "rec-ttlreq")

    updated = _poll_until(probe_updated, lambda r: r is not None and r.get("feature_a") == "updated-with-ttl", timeout_s=30.0)
    assert updated["feature_a"] == "updated-with-ttl", (
        f"UpdateRecord with TtlDuration and EventTime together must succeed; expected "
        f"feature_a='updated-with-ttl', got {updated['feature_a']!r}"
    )


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
    online_store_config = {"EnableOnlineStore": True, "StorageType": "Standard_V2"}
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
