"""feature-group-create-describe-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-group-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A FeatureGroup transitions Creating->Created and is deleted, releasing its definitions."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-behav-fg-").replace("-", "_")

    sm.create_feature_group(
        FeatureGroupName=name,
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
    ctx.on_cleanup(lambda: _delete_fg_best_effort(sm, name))

    desc = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=name),
        lambda d: d["FeatureGroupStatus"] in ("Created", "CreateFailed"),
        timeout_s=120,
        interval_s=3,
    )
    assert desc["FeatureGroupStatus"] == "Created", (
        f"expected FeatureGroupStatus=Created, got {desc['FeatureGroupStatus']!r} "
        f"(FailureReason={desc.get('FailureReason')!r})"
    )
    assert desc["RecordIdentifierFeatureName"] == "record_id", (
        f"expected RecordIdentifierFeatureName='record_id', got {desc['RecordIdentifierFeatureName']!r}"
    )
    assert desc["EventTimeFeatureName"] == "event_time", (
        f"expected EventTimeFeatureName='event_time', got {desc['EventTimeFeatureName']!r}"
    )
    assert len(desc["FeatureDefinitions"]) == 3, (
        f"expected 3 FeatureDefinitions, got {len(desc['FeatureDefinitions'])}: {desc['FeatureDefinitions']!r}"
    )

    sm.delete_feature_group(FeatureGroupName=name)

    code, message = _poll_gone(
        lambda: sm.describe_feature_group(FeatureGroupName=name), timeout_s=120, interval_s=3
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    assert message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {name}", f"unexpected DescribeFeatureGroup message: {message!r}"

    second_delete_code, second_delete_message = _error(
        lambda: sm.delete_feature_group(FeatureGroupName=name)
    )
    assert second_delete_code == "ResourceNotFound", (
        f"expected a delete of an already-deleted FeatureGroup to also fail with "
        f"ResourceNotFound, got {second_delete_code!r}"
    )
    assert second_delete_message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {name}", (
        f"unexpected second DeleteFeatureGroup message: {second_delete_message!r}"
    )


def _delete_fg_best_effort(sm, name: str) -> None:
    try:
        sm.delete_feature_group(FeatureGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _poll_gone(fn, *, timeout_s: float, interval_s: float):
    """Poll fn() until it is refused and return the refusal's (code, message); the delete is
    asynchronous, so a success inside the window is retried and one that outlasts it raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the deleted resource was still readable after {timeout_s}s: {last!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
