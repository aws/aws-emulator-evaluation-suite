"""get-record-expiration-time-response-disabled-by-default."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-record-expiration-time-response-disabled-by-default"
GROUP = "ttl"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetRecord on a record written with a TtlDuration omits ExpiresAt by default and returns a
    populated ExpiresAt when ExpirationTimeResponse is Enabled."""
    fg_name = _create_online_feature_group(ctx)
    t0 = time.time()
    fsr = ctx.client("sagemaker-featurestore-runtime")
    fsr.put_record(
        FeatureGroupName=fg_name,
        Record=[
            {"FeatureName": "record_id", "ValueAsString": "rec-noexp"},
            {"FeatureName": "event_time", "ValueAsString": str(t0)},
            {"FeatureName": "feature_a", "ValueAsString": "expiring"},
        ],
        TtlDuration={"Unit": "Hours", "Value": 2},
    )

    def probe():
        return fsr.get_record(FeatureGroupName=fg_name, RecordIdentifierValueAsString="rec-noexp")

    resp = _poll_until(probe, lambda r: "Record" in r, timeout_s=30.0)
    assert "ExpiresAt" not in resp or not resp["ExpiresAt"], f"expected no ExpiresAt by default, got {resp}"

    # Positive control: the same record returns a populated ExpiresAt once ExpirationTimeResponse is
    # Enabled, so the default omission is not a target that never computes ExpiresAt.
    enabled_resp = fsr.get_record(
        FeatureGroupName=fg_name,
        RecordIdentifierValueAsString="rec-noexp",
        ExpirationTimeResponse="Enabled",
    )
    assert enabled_resp.get("ExpiresAt"), (
        f"expected a populated ExpiresAt when ExpirationTimeResponse='Enabled' was requested for "
        f"a record written with TtlDuration, got {enabled_resp}"
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_feature_group(ctx, name))
    _wait_for_feature_group_status(ctx, name, "Created")
    return name


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
