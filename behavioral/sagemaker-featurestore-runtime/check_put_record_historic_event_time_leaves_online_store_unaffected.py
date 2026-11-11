"""put-record-historic-event-time-leaves-online-store-unaffected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-record-historic-event-time-leaves-online-store-unaffected"
GROUP = "state-transitions"
SERVICES = ["sagemaker-featurestore-runtime"]


@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRecord with an EventTime not later than the stored one leaves the online store's latest record
    unchanged across repeated reads over the absence window, while a later newer write is read back."""
    fg_name = _create_online_feature_group(ctx)
    t_latest = time.time()
    t_put_start = time.monotonic()
    _put_record(ctx, fg_name, "rec-hist", t_latest, {"feature_a": "latest-value"})

    def probe_latest():
        return _get_record_dict(ctx, fg_name, "rec-hist")

    latest = _poll_until(probe_latest, lambda r: r is not None and r.get("feature_a") == "latest-value", timeout_s=30.0)
    latency_s = time.monotonic() - t_put_start
    assert latest["event_time"] == str(t_latest), (
        f"GetRecord returned event_time={latest['event_time']!r}, expected {t_latest!r} for the "
        f"record just written"
    )

    # A "historic" write with an earlier EventTime must not affect the OnlineStore latest record.
    t_historic = t_latest - 1000
    _put_record(ctx, fg_name, "rec-hist", t_historic, {"feature_a": "historic-value"})

    # Hold absence for a window calibrated off the measured convergence latency above, sampling
    # repeatedly -- a single sample after a fixed sleep cannot tell "correctly ignored" from
    # "not yet processed, but about to be applied".
    window_s = max(3.0 * latency_s, 10.0)
    deadline = time.monotonic() + window_s
    samples = 0
    while time.monotonic() < deadline:
        snap = _get_record_dict(ctx, fg_name, "rec-hist")
        assert (
            snap is not None
            and snap.get("feature_a") == "latest-value"
            and snap.get("event_time") == str(t_latest)
        ), (
            f"a PutRecord whose EventTime ({t_historic!r}) is not greater than the stored "
            f"EventTime ({t_latest!r}) mutated the OnlineStore latest record: {snap!r}, expected "
            f"feature_a='latest-value' event_time={t_latest!r} unchanged"
        )
        samples += 1
        time.sleep(1.5)
    assert samples >= 3, (
        f"only {samples} sample(s) were taken over the {window_s:.1f}s absence window; too few "
        f"to be a meaningful absence check"
    )

    # Positive control: a genuinely NEWER write on the same wiring must still land, which is
    # what separates "event-time ordering enforced" from "the OnlineStore pipeline is stalled".
    t_newest = t_latest + 1000
    _put_record(ctx, fg_name, "rec-hist", t_newest, {"feature_a": "newest-value"})

    def probe_newest():
        return _get_record_dict(ctx, fg_name, "rec-hist")

    newest = _poll_until(probe_newest, lambda r: r is not None and r.get("feature_a") == "newest-value", timeout_s=30.0)
    assert newest["event_time"] == str(t_newest), (
        f"GetRecord returned event_time={newest['event_time']!r}, expected {t_newest!r} after the "
        f"positive-control write that must apply"
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
        Tags=[{"Key": "sim2real", "Value": "featurestore-historic-event-time"}],
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
