"""put-model-package-group-policy-precondition-conflict."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-precondition-conflict"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy on a missing model package group returns ValidationException
    (not ConflictException) naming the group's ARN, the group describes as ValidationException
    "does not exist", and the same call on a real group succeeds (positive control)."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    missing_group_name = ctx.unique_name("sim2real-mpg-missing-")
    missing_policy = json.dumps(_policy_for(ctx, account_id, missing_group_name))

    # (a) breaking one thing: target a group that was never created
    code, message = _error_code_and_message(
        lambda: sm.put_model_package_group_policy(
            ModelPackageGroupName=missing_group_name, ResourcePolicy=missing_policy
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    # the exact message separates "group not found" from other ValidationException causes that share
    # the same error code.
    missing_group_arn = _group_arn(ctx, account_id, missing_group_name)
    expected_message = f"Cannot find Model Package Group: {missing_group_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (b) effect absent: no group was created as a side effect, and there is no policy
    described_code, described_message = _error_code_and_message(
        lambda: sm.describe_model_package_group(ModelPackageGroupName=missing_group_name)
    )
    assert described_code == "ValidationException", (
        f"expected the never-created group {missing_group_name!r} to describe as "
        f"ValidationException, got {described_code!r}"
    )
    expected_described = f"ModelPackageGroup {missing_group_arn} does not exist."
    assert described_message == expected_described, (
        f"expected message {expected_described!r}, got {described_message!r}"
    )

    # (c) positive control: the exact same call succeeds against a real group
    real_group_name = ctx.unique_name("sim2real-mpg-real-")
    sm.create_model_package_group(
        ModelPackageGroupName=real_group_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_group(sm, real_group_name))
    real_policy = _policy_for(ctx, account_id, real_group_name)
    sm.put_model_package_group_policy(
        ModelPackageGroupName=real_group_name, ResourcePolicy=json.dumps(real_policy)
    )
    fetched = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=real_group_name)["ResourcePolicy"]
    )
    assert fetched["Statement"][0]["Sid"] == real_policy["Statement"][0]["Sid"], (
        f"expected the fetched policy Sid to be {real_policy['Statement'][0]['Sid']!r}, "
        f"got {fetched['Statement'][0].get('Sid')!r}"
    )


def _group_arn(ctx, account_id: str, group_name: str) -> str:
    return f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"


def _policy_for(ctx, account_id: str, group_name: str) -> dict:
    group_arn = _group_arn(ctx, account_id, group_name)
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sagemaker:DescribeModelPackageGroup"],
                "Resource": group_arn,
            }
        ],
    }


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_group(sm, name):
    _delete_if_present(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=name))
    _delete_if_present(lambda: sm.delete_model_package_group(ModelPackageGroupName=name))


_GONE_MARKERS = ("does not exist", "not found", "cannot find")


def _delete_if_present(fn) -> None:
    """Teardown delete: returns when SageMaker reports the resource is already gone and
    raises any other failure."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        message = err.get("Message", "").lower()
        gone = err["Code"] == "ResourceNotFound" or (
            err["Code"] == "ValidationException" and any(m in message for m in _GONE_MARKERS)
        )
        if not gone:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
