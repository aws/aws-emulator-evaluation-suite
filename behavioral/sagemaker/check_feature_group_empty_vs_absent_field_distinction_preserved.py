"""feature-group-empty-vs-absent-field-distinction-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "feature-group-empty-vs-absent-field-distinction-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]

_FEATURE_DEFINITIONS = [
    {"FeatureName": "record_id", "FeatureType": "String"},
    {"FeatureName": "event_time", "FeatureType": "String"},
]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A FeatureGroup tag with an empty-string Value reads back as that key with Value "" (exactly one
    tag), while a feature group created without the tag reads back no tags, so an empty value is not
    collapsed into absence.
    """
    sm = ctx.client("sagemaker")

    empty_tag_key = ctx.unique_name("sim2real-tagempty").replace("_", "-")

    name_with_empty = ctx.unique_name("sim2real-fg-empty-")
    fg_arn_empty = sm.create_feature_group(
        FeatureGroupName=name_with_empty,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=_FEATURE_DEFINITIONS,
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": empty_tag_key, "Value": ""}],
    )["FeatureGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_feature_group(FeatureGroupName=name_with_empty))

    name_absent = ctx.unique_name("sim2real-fg-absent-")
    fg_arn_absent = sm.create_feature_group(
        FeatureGroupName=name_absent,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=_FEATURE_DEFINITIONS,
        OnlineStoreConfig={"EnableOnlineStore": True},
    )["FeatureGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_feature_group(FeatureGroupName=name_absent))

    tags_empty = _poll_until(
        probe=lambda: sm.list_tags(ResourceArn=fg_arn_empty)["Tags"],
        predicate=lambda tags: any(t["Key"] == empty_tag_key for t in tags),
        timeout_s=60.0,
        interval_s=5.0,
    )
    tags_absent = sm.list_tags(ResourceArn=fg_arn_absent)["Tags"]

    empty_match = [t for t in tags_empty if t["Key"] == empty_tag_key]
    assert empty_match and empty_match[0]["Value"] == "", (
        f"expected an explicit empty-string tag value to round-trip, got {tags_empty!r}"
    )
    assert len(tags_empty) == 1, (
        f"expected exactly the one explicit empty-string tag, got {tags_empty!r}"
    )
    assert tags_absent == [], (
        f"a feature group that was never tagged must list zero tags, not materialize any: {tags_absent!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    import time

    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    raise TimeoutError(
        f"predicate never satisfied within {timeout_s}s; last observed value: {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
