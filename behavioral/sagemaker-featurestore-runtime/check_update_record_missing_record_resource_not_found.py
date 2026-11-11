"""update-record-missing-record-resource-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-record-missing-record-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateRecord on a never-ingested RecordIdentifier fails with ResourceNotFound and a nonexistent
    FeatureGroupName fails with ValidationError, each with its exact message, while UpdateRecord on an
    existing record applies the new value."""
    fg_name = _create_online_feature_group(ctx)
    fsr = ctx.client("sagemaker-featurestore-runtime")

    code, message = _error(
        lambda: fsr.update_record(
            FeatureGroupName=fg_name,
            RecordIdentifierValueAsString="rec-never-ingested",
            Features=[
                {"FeatureName": "event_time", "ValueAsString": str(time.time())},
                {"FeatureName": "feature_a", "ValueAsString": "x"},
            ],
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound for a never-ingested record, got {code!r}"
    expected = "Record Not Found: Record not found with record identifier [rec-never-ingested]."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # feature-group-level absence is a different failure than record-level absence:
    # a nonexistent FeatureGroupName is rejected before the service ever looks for the
    # record, so it must not come back as the same ResourceNotFound code asserted above.
    bogus_fg = ctx.unique_name("sim2real-fsr-missing-")
    fg_code, fg_message = _error(
        lambda: fsr.update_record(
            FeatureGroupName=bogus_fg,
            RecordIdentifierValueAsString="rec-never-ingested",
            Features=[
                {"FeatureName": "event_time", "ValueAsString": str(time.time())},
                {"FeatureName": "feature_a", "ValueAsString": "x"},
            ],
        )
    )
    assert fg_code == "ValidationError", f"expected ValidationError for nonexistent FeatureGroupName, got {fg_code!r}"
    fg_expected = (
        f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name "
        f"[arn:aws:sagemaker:{ctx.region}:{ctx.account}:feature-group/{bogus_fg}]."
    )
    assert fg_message == fg_expected, f"expected message {fg_expected!r}, got {fg_message!r}"

    # positive control: same FeatureGroup, but the record actually exists
    t0 = time.time()
    _put_record(ctx, fg_name, "rec-exists", t0, {"feature_a": "a1"})

    def probe_exists():
        return _get_record_dict(ctx, fg_name, "rec-exists")

    _poll_until(probe_exists, lambda r: r is not None, timeout_s=30.0)

    fsr.update_record(
        FeatureGroupName=fg_name,
        RecordIdentifierValueAsString="rec-exists",
        Features=[
            {"FeatureName": "event_time", "ValueAsString": str(t0 + 10)},
            {"FeatureName": "feature_a", "ValueAsString": "a2"},
        ],
    )

    def probe_updated():
        return _get_record_dict(ctx, fg_name, "rec-exists")

    updated = _poll_until(probe_updated, lambda r: r is not None and r.get("feature_a") == "a2", timeout_s=30.0)
    assert updated["feature_a"] == "a2", f"expected feature_a='a2' after UpdateRecord, got {updated!r}"


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
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
