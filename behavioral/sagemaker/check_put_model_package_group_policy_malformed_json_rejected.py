"""put-model-package-group-policy-malformed-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-malformed-json-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy rejects a non-JSON ResourcePolicy with ValidationException and
    leaves the group with no policy, while the same call with a well-formed policy succeeds
    (control), so the refusal is specific to the malformed body."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-mpg-badjson-")

    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _delete_group(sm, group_name))

    malformed_policy = '{"Version": "2012-10-17", "Statement": [ this is not json ] :::'
    code, message = _error(
        lambda: sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=malformed_policy
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "Invalid Policy: This policy contains invalid Json"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (b) effect absent: no policy was ever stored for the group. SageMaker's
    # GetModelPackageGroupPolicy reports "no policy attached" as ValidationException,
    # not a not-found code (confirmed against real AWS; there is no 404-style variant
    # on this read path).
    absent_code, absent_message = _error(
        lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    )
    assert absent_code == "ValidationException", f"expected ValidationException, got {absent_code}"
    expected_absent = f"Cannot find resource policy for: {group_arn}"
    assert absent_message == expected_absent, (
        f"expected message {expected_absent!r}, got {absent_message!r}"
    )

    # (c) positive control: a well-formed policy on the exact same group succeeds.
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": group_arn,
            }
        ],
    }
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(valid_policy)
    )
    ctx.on_cleanup(lambda: _delete_policy_quiet(sm, group_name))

    # SageMaker re-serializes the stored document (compact separators), so compare
    # parsed JSON rather than raw bytes (confirmed against real AWS).
    got = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert got == valid_policy, f"expected the well-formed policy to persist, got {got!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_group(sm, name: str) -> None:
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


def _delete_policy_quiet(sm, name: str) -> None:
    try:
        sm.delete_model_package_group_policy(ModelPackageGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
