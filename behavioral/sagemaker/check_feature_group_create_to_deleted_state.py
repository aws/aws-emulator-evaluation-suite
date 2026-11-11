"""feature-group-create-to-deleted-state."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "feature-group-create-to-deleted-state"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FeatureGroup moves Creating->Created, then Deleting, then 404s after DeleteFeatureGroup."""
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-fg-")

    create_resp = sm.create_feature_group(
        FeatureGroupName=name,
        RecordIdentifierFeatureName="record_id",
        EventTimeFeatureName="event_time",
        FeatureDefinitions=[
            {"FeatureName": "record_id", "FeatureType": "String"},
            {"FeatureName": "event_time", "FeatureType": "String"},
        ],
        OnlineStoreConfig={"EnableOnlineStore": True},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    feature_group_arn = create_resp["FeatureGroupArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_feature_group(FeatureGroupName=name)))

    status = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=name)["FeatureGroupStatus"],
        lambda s: s in ("Created", "CreateFailed"),
        timeout_s=180,
        interval_s=5,
    )
    assert status == "Created", f"expected FeatureGroupStatus=Created, got {status}"

    described = sm.describe_feature_group(FeatureGroupName=name)
    assert described["FeatureGroupArn"] == feature_group_arn
    assert described["RecordIdentifierFeatureName"] == "record_id"
    assert described["OnlineStoreConfig"]["EnableOnlineStore"] is True

    sm.delete_feature_group(FeatureGroupName=name)

    code, message = _poll_gone(
        lambda: sm.describe_feature_group(FeatureGroupName=name), timeout_s=120, interval_s=5
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    assert message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {name}", f"unexpected DescribeFeatureGroup message: {message!r}"

    mutation_code, mutation_message = _error(
        lambda: sm.update_feature_group(
            FeatureGroupName=name,
            FeatureAdditions=[{"FeatureName": "extra_feature", "FeatureType": "String"}],
        )
    )
    assert mutation_code == "ResourceNotFound", (
        f"expected UpdateFeatureGroup on a deleted group to fail with ResourceNotFound, got {mutation_code}"
    )
    assert mutation_message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {name}", f"unexpected UpdateFeatureGroup message: {mutation_message!r}"


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


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
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
