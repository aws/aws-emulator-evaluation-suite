"""feature-group-event-timestamp-preserved."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "feature-group-event-timestamp-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]

_EVENT_TIME_VALUE = "2024-03-15T12:30:45.123456Z"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A record's EventTimeFeatureName value written with microsecond precision reads back from
    the Feature Store online store as the same literal, with no timezone conversion and no
    truncation to whole seconds."""
    sm = ctx.client("sagemaker")
    fs_runtime = ctx.client("sagemaker-featurestore-runtime")

    group_name = ctx.unique_name("sim2real-fg-")
    sm.create_feature_group(
        FeatureGroupName=group_name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "String"},
            {"FeatureName": "value", "FeatureType": "Fractional"},
        ],
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_feature_group_and_confirm_gone(sm, group_name))

    desc = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=group_name),
        lambda d: d["FeatureGroupStatus"] in ("Created", "CreateFailed"),
        timeout_s=120,
        interval_s=3,
    )
    assert desc["FeatureGroupStatus"] == "Created", desc.get("FailureReason")
    assert desc["EventTimeFeatureName"] == "event_time", desc["EventTimeFeatureName"]
    assert desc["RecordIdentifierFeatureName"] == "record_id", desc["RecordIdentifierFeatureName"]

    record_id = ctx.unique_name("rec-")
    fs_runtime.put_record(
        FeatureGroupName=group_name,
        Record=[
            {"FeatureName": "record_id", "ValueAsString": record_id},
            {"FeatureName": "event_time", "ValueAsString": _EVENT_TIME_VALUE},
            {"FeatureName": "value", "ValueAsString": "42.5"},
        ],
    )

    got = _poll_until(
        lambda: fs_runtime.get_record(
            FeatureGroupName=group_name,
            RecordIdentifierValueAsString=record_id,
        ),
        lambda r: r.get("Record") is not None,
        timeout_s=60,
        interval_s=2,
    )
    record_by_name = {f["FeatureName"]: f["ValueAsString"] for f in got["Record"]}
    assert record_by_name["event_time"] == _EVENT_TIME_VALUE, record_by_name["event_time"]
    assert record_by_name["record_id"] == record_id, record_by_name["record_id"]
    assert record_by_name["value"] == "42.5", record_by_name["value"]


# ===== helpers =====


def _delete_feature_group_and_confirm_gone(sm, group_name: str) -> None:
    from botocore.exceptions import ClientError

    sm.delete_feature_group(FeatureGroupName=group_name)

    def _probe():
        try:
            sm.describe_feature_group(FeatureGroupName=group_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFound":
                return "ResourceNotFound"
            raise
        return None

    _poll_until(
        _probe,
        lambda code: code == "ResourceNotFound",
        timeout_s=120,
        interval_s=3,
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
