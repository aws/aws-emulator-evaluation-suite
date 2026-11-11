"""create-feature-group-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-feature-group-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateFeatureGroup call with a name identical to an existing feature group is
    rejected, not silently coalesced into (or allowed to mutate) the existing group."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-fg-")
    feature_defs = [
        {"FeatureName": "record_id", "FeatureType": "String"},
        {"FeatureName": "event_time", "FeatureType": "Fractional"},
    ]

    first = sm.create_feature_group(
        FeatureGroupName=name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=feature_defs,
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_feature_group_when_settled(sm, name))
    original_arn = first["FeatureGroupArn"]
    before = sm.describe_feature_group(FeatureGroupName=name)

    code = message = None
    try:
        dup = sm.create_feature_group(
            FeatureGroupName=name,
            RecordIdentifierFeatureName="record_id",
            EventTimeFeatureName="event_time",
            FeatureDefinitions=[
                {"FeatureName": "record_id", "FeatureType": "String"},
                {"FeatureName": "event_time", "FeatureType": "Fractional"},
                {"FeatureName": "extra_feature", "FeatureType": "Integral"},
            ],
            OnlineStoreConfig={"EnableOnlineStore": True},
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"duplicate CreateFeatureGroup SUCCEEDED and returned {dup!r}")

    assert code == "ResourceInUse", f"unexpected code for duplicate feature group name: {code}"
    expected = (
        f"Resource Already Exists: FeatureGroup with name {name} already exists. "
        "Choose a different name."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = sm.describe_feature_group(FeatureGroupName=name)
    assert after["FeatureGroupArn"] == original_arn, "duplicate create call replaced the original group's ARN"
    assert [fd["FeatureName"] for fd in after["FeatureDefinitions"]] == [
        fd["FeatureName"] for fd in before["FeatureDefinitions"]
    ], "the duplicate create call mutated the original feature group's schema"

    other_name = ctx.unique_name("sim2real-fg-other-")
    sm.create_feature_group(
        FeatureGroupName=other_name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=feature_defs,
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_feature_group_when_settled(sm, other_name))
    other_desc = sm.describe_feature_group(FeatureGroupName=other_name)
    assert other_desc["FeatureGroupName"] == other_name, (
        f"positive control feature group not describable under its own name: {other_desc.get('FeatureGroupName')!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError:
        pass


def _delete_feature_group_when_settled(sm, name, timeout_s=600.0, interval_s=5.0):
    """DeleteFeatureGroup refuses a group that is still Creating, so wait for a settled
    status (bounded, raising on timeout) and then delete; a group already gone is fine."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = sm.describe_feature_group(FeatureGroupName=name)["FeatureGroupStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        if status == "Deleting":
            return
        if status != "Creating":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"feature group {name} still {status} after {timeout_s}s")
        time.sleep(interval_s)
    sm.delete_feature_group(FeatureGroupName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
