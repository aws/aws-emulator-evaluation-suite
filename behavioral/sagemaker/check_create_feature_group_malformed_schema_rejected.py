"""create-feature-group-malformed-schema-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-feature-group-malformed-schema-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFeatureGroup with an Integral EventTimeFeatureName fails with ValidationException and the
    exact message and creates nothing, while the same schema with a valid event-time type reaches
    Created."""
    sm = ctx.client("sagemaker")

    # --- negative: event_time feature typed Integral, which is not a valid
    # EventTime type (String or Fractional only) ---
    bad_group_name = ctx.unique_name("sim2real-bad-fg-")
    code, message = _error(
        lambda: sm.create_feature_group(
            FeatureGroupName=bad_group_name,
            RecordIdentifierFeatureName="record_id",
            EventTimeFeatureName="event_time",
            FeatureDefinitions=[
                {"FeatureName": "record_id", "FeatureType": "String"},
                {"FeatureName": "event_time", "FeatureType": "Integral"},
            ],
            OnlineStoreConfig={"EnableOnlineStore": True},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "Validation Error: invalid event time event_time feature type provided Integral. "
        "Event time type should be either Fractional(Unix timestamp in seconds) or String "
        "(ISO-8601 format) type"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no feature group was created under that name
    describe_code, describe_message = _error(
        lambda: sm.describe_feature_group(FeatureGroupName=bad_group_name)
    )
    assert describe_code == "ResourceNotFound", (
        f"expected DescribeFeatureGroup to report ResourceNotFound for a feature "
        f"group that was never created, got {describe_code}"
    )
    expected_describe = (
        f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {bad_group_name}"
    )
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # --- positive control: a schema with a valid event-time type succeeds ---
    good_group_name = ctx.unique_name("sim2real-good-fg-")
    resp = sm.create_feature_group(
        FeatureGroupName=good_group_name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "Fractional"},
        ],
        OnlineStoreConfig={"EnableOnlineStore": True},
    )
    assert resp["FeatureGroupArn"], f"expected a FeatureGroupArn, got {resp!r}"
    ctx.on_cleanup(lambda: sm.delete_feature_group(FeatureGroupName=good_group_name))

    described = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=good_group_name),
        lambda d: d["FeatureGroupStatus"] in ("Created", "CreateFailed"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert described["FeatureGroupStatus"] == "Created", (
        f"expected the well-typed feature group to reach Created, "
        f"got {described['FeatureGroupStatus']} ({described.get('FailureReason')!r})"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
