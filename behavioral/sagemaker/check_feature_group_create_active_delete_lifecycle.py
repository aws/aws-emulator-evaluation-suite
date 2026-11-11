"""feature-group-create-active-delete-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "feature-group-create-active-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFeatureGroup (online-store only) transitions Creating->Created, DescribeFeatureGroup
    reflects status, DeleteFeatureGroup transitions to Deleting then 404s."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    role_arn = _create_execution_role(ctx, iam)

    fg_name = ctx.unique_name("sim2real-sm-fg-")

    def _create():
        return sm.create_feature_group(
            FeatureGroupName=fg_name,
            RecordIdentifierFeatureName="record_id",
            EventTimeFeatureName="event_time",
            FeatureDefinitions=[
                {"FeatureName": "record_id", "FeatureType": "String"},
                {"FeatureName": "event_time", "FeatureType": "String"},
                {"FeatureName": "value", "FeatureType": "Fractional"},
            ],
            OnlineStoreConfig={"EnableOnlineStore": True},
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    created = _retry_role_propagation(_create)
    fg_arn = created["FeatureGroupArn"]
    ctx.on_cleanup(lambda: _delete_feature_group_if_present(ctx, fg_name))

    described = _poll_until(
        lambda: sm.describe_feature_group(FeatureGroupName=fg_name),
        lambda r: r["FeatureGroupStatus"] in ("Created", "CreateFailed"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert described["FeatureGroupStatus"] == "Created", described.get("FailureReason")
    assert described["FeatureGroupArn"] == fg_arn
    assert described["RecordIdentifierFeatureName"] == "record_id"
    assert described["RoleArn"] == role_arn, (
        f"expected the execution role to be represented back, got {described.get('RoleArn')!r}"
    )

    sm.delete_feature_group(FeatureGroupName=fg_name)

    code, message = _poll_gone(
        lambda: sm.describe_feature_group(FeatureGroupName=fg_name), timeout_s=180.0, interval_s=5.0
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    assert message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {fg_name}", f"unexpected DescribeFeatureGroup message: {message!r}"

    second_delete_code, second_delete_message = _error(
        lambda: sm.delete_feature_group(FeatureGroupName=fg_name)
    )
    assert second_delete_code == "ResourceNotFound", (
        f"a mutation on the already-deleted feature group must still fail not-found, "
        f"got {second_delete_code!r}"
    )
    assert second_delete_message == f"Resource Not Found: Amazon SageMaker can't find a FeatureGroup with name {fg_name}", (
        f"unexpected second DeleteFeatureGroup message: {second_delete_message!r}"
    )


def _delete_feature_group_if_present(ctx, fg_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_feature_group(FeatureGroupName=fg_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _poll_gone(fn, *, timeout_s: float, interval_s: float):
    """Poll fn() until it is refused and return the refusal's (code, message); the delete is
    asynchronous, so a success inside the window is retried and one that outlasts it raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the deleted resource was still readable after {timeout_s}s: {last!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
