"""feature-group-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-group-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFeatureGroup with a name that already exists is rejected with ResourceInUse,
    leaves the original feature group's definition untouched, and a differently-named
    feature group can still be created normally (positive control)."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-fg-dup-")

    created = sm.create_feature_group(
        FeatureGroupName=name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "String"},
        ],
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    original_arn = created["FeatureGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_feature_group(FeatureGroupName=name)))

    status = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=name)["FeatureGroupStatus"],
        lambda s: s in ("Created", "CreateFailed"),
        timeout_s=180,
        interval_s=5,
    )
    assert status == "Created", f"prerequisite feature group failed to create: {status}"
    before = sm.describe_feature_group(FeatureGroupName=name)

    code, message = _error(
        lambda: sm.create_feature_group(
            FeatureGroupName=name,
            RecordIdentifierFeatureName="other_id",
            EventTimeFeatureName="other_time",
            FeatureDefinitions=[
                {"FeatureName": "other_id", "FeatureType": "String"},
                {"FeatureName": "other_time", "FeatureType": "String"},
            ],
            OnlineStoreConfig={"EnableOnlineStore": True},
        )
    )
    assert code == "ResourceInUse", f"expected ResourceInUse for duplicate name, got {code}"
    assert message == (
        f"Resource Already Exists: FeatureGroup with name {name} already exists. Choose a different name."
    ), f"unexpected duplicate CreateFeatureGroup message: {message!r}"

    # Effect absent: the original feature group's identity and schema were not overwritten.
    described = sm.describe_feature_group(FeatureGroupName=name)
    assert described["FeatureGroupArn"] == original_arn, (
        f"duplicate create call replaced the original ARN: {original_arn!r} -> {described['FeatureGroupArn']!r}"
    )
    assert described["RecordIdentifierFeatureName"] == "record_id", (
        f"expected RecordIdentifierFeatureName unchanged at 'record_id', got {described['RecordIdentifierFeatureName']!r}"
    )
    assert described["EventTimeFeatureName"] == "event_time", (
        f"expected EventTimeFeatureName unchanged at 'event_time', got {described['EventTimeFeatureName']!r}"
    )
    assert [fd["FeatureName"] for fd in described["FeatureDefinitions"]] == [
        fd["FeatureName"] for fd in before["FeatureDefinitions"]
    ], "duplicate create call mutated the original feature group's schema"

    # Positive control: a differently-named feature group still creates normally.
    control_name = ctx.unique_name("sim2real-fg-ctrl-")
    sm.create_feature_group(
        FeatureGroupName=control_name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "String"},
        ],
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_feature_group(FeatureGroupName=control_name)))
    control_status = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=control_name)["FeatureGroupStatus"],
        lambda s: s in ("Created", "CreateFailed"),
        timeout_s=180,
        interval_s=5,
    )
    assert control_status == "Created", f"positive control feature group failed: {control_status}"


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
