"""put-record-ttl-duration-sets-expires-at."""
from __future__ import annotations

import time
from datetime import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-record-ttl-duration-sets-expires-at"
GROUP = "ttl"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord with a TtlDuration causes GetRecord(ExpirationTimeResponse='Enabled') to
    return an ExpiresAt timestamp that is in the future and consistent with the write
    time plus the TtlDuration, not merely a non-empty string."""
    fg_name = _create_online_feature_group(ctx)
    ttl_hours = 2
    t_before = time.time()
    fsr = ctx.client("sagemaker-featurestore-runtime")
    fsr.put_record(
        FeatureGroupName=fg_name,
        Record=[
            {"FeatureName": "record_id", "ValueAsString": "rec-ttl"},
            {"FeatureName": "event_time", "ValueAsString": str(t_before)},
            {"FeatureName": "feature_a", "ValueAsString": "expiring"},
        ],
        TtlDuration={"Unit": "Hours", "Value": ttl_hours},
    )
    t_after = time.time()

    def probe():
        resp = fsr.get_record(
            FeatureGroupName=fg_name,
            RecordIdentifierValueAsString="rec-ttl",
            ExpirationTimeResponse="Enabled",
        )
        return resp

    resp = _poll_until(probe, lambda r: "Record" in r, timeout_s=30.0)
    expires_at = resp.get("ExpiresAt")
    assert expires_at, f"expected a non-empty ExpiresAt when TtlDuration was set, got {resp!r}"

    expires_epoch = datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
    now = time.time()
    assert expires_epoch > now, f"expected ExpiresAt {expires_at!r} to be in the future (now={now})"

    ttl_seconds = ttl_hours * 3600
    window_start = t_before + ttl_seconds - 60
    window_end = t_after + ttl_seconds + 60
    assert window_start <= expires_epoch <= window_end, (
        f"expected ExpiresAt {expires_at!r} (epoch={expires_epoch}) to fall within "
        f"[{window_start}, {window_end}] i.e. write time + {ttl_hours}h, got outside that window"
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
