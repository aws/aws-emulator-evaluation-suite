"""feature-group-create-active-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-group-create-active-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFeatureGroup moves FeatureGroupStatus Creating -> Created and DeleteFeatureGroup
    removes it permanently (subsequent DescribeFeatureGroup returns ResourceNotFound)."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-sm-fg-")

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_feature_group(FeatureGroupName=name)))
    sm.create_feature_group(
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

    created = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=name),
        lambda d: d["FeatureGroupStatus"] in ("Created", "CreateFailed"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert created["FeatureGroupStatus"] == "Created", (
        f"expected FeatureGroupStatus=Created, got {created['FeatureGroupStatus']!r} "
        f"(FailureReason={created.get('FailureReason')!r})"
    )
    assert created["FeatureGroupName"] == name, f"expected FeatureGroupName={name!r}, got {created['FeatureGroupName']!r}"
    assert created["RecordIdentifierFeatureName"] == "record_id", (
        f"expected RecordIdentifierFeatureName='record_id', got {created['RecordIdentifierFeatureName']!r}"
    )

    sm.delete_feature_group(FeatureGroupName=name)

    code, message = _poll_gone(
        lambda: sm.describe_feature_group(FeatureGroupName=name), timeout_s=120.0, interval_s=5.0
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    assert message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {name}", f"unexpected DescribeFeatureGroup message: {message!r}"

    update_code, update_message = _error(
        lambda: sm.update_feature_group(
            FeatureGroupName=name,
            FeatureAdditions=[{"FeatureName": "late_addition", "FeatureType": "String"}],
        )
    )
    assert update_code == "ResourceNotFound", (
        f"expected a mutation on the deleted FeatureGroupName to fail with ResourceNotFound, got {update_code!r}"
    )
    assert update_message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {name}", f"unexpected UpdateFeatureGroup message: {update_message!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _poll_gone(fn, *, timeout_s: float, interval_s: float):
    """Poll fn() until it is refused and return the refusal's (code, message); the delete is
    asynchronous, so a success inside the window is retried and one that outlasts it raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the deleted resource was still readable after {timeout_s}s: {last!r}")


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
