"""put-model-package-group-policy-invalid-json-conflict."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-invalid-json-conflict"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy with a non-JSON resource policy is rejected with
    ValidationException and leaves the stored policy intact; a later well-formed policy still
    applies (positive control)."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-")
    resp = sm.create_model_package_group(ModelPackageGroupName=group_name)
    group_arn = resp["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _delete_if_present(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name)))
    ctx.on_cleanup(
        lambda: _delete_if_present(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name))
    )

    original_policy = _valid_policy(account_id, group_arn, "sagemaker:DescribeModelPackageGroup")
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(original_policy)
    )

    # Break exactly one thing: submit a syntactically invalid (non-JSON) policy.
    code, message = _error(
        lambda: sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy="{this is not valid json"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid Policy: This policy contains invalid Json", message

    # Effect absent: the previously-set, valid policy is still in place, unchanged.
    current = json.loads(sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"])
    assert current == original_policy, (
        f"malformed Put must not overwrite the stored policy; got {current!r}"
    )

    # Positive control: a new, well-formed policy still applies successfully.
    updated_policy = _valid_policy(account_id, group_arn, "sagemaker:DescribeModelPackage")
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(updated_policy)
    )
    current2 = json.loads(sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"])
    assert current2 == updated_policy, (
        f"expected the well-formed Put to persist, got {current2!r}"
    )


def _valid_policy(account_id: str, group_arn: str, action: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealAllow",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": action,
                "Resource": group_arn,
            }
        ],
    }


def _error(fn) -> tuple[str, str]:
    """Call fn(); return (code, message) of its ClientError. An unexpected success raises, so
    accepting what AWS refuses fails rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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
