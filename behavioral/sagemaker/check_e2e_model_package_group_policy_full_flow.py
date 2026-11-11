"""e2e-model-package-group-policy-full-flow."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "e2e-model-package-group-policy-full-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Full flow: create a model package group, attach a resource policy, read it back
    (proving the account can enforce/inspect a cross-account-style grant), delete the
    policy, and confirm the group no longer has any policy attached."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ModelPackageGroupArn"]

    def _cleanup_group() -> None:
        from botocore.exceptions import ClientError

        try:
            sm.delete_model_package_group(ModelPackageGroupName=group_name)
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup_group)

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CrossAccountDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sagemaker:DescribeModelPackageGroup", "sagemaker:ListModelPackages"],
                "Resource": group_arn,
            }
        ],
    }
    policy_str = json.dumps(policy_doc)

    put_resp = sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=policy_str
    )
    assert put_resp["ModelPackageGroupArn"] == group_arn, (
        f"expected PutModelPackageGroupPolicy to echo {group_arn!r}, got "
        f"{put_resp['ModelPackageGroupArn']!r}"
    )

    # Confirm the attached policy is readable back exactly as attached -- this is the
    # mechanism a cross-account principal relies on to know it has been granted access.
    # SageMaker re-serializes the document (compact, key order preserved) rather than
    # echoing the exact bytes PUT, so the invariant is JSON equality, not byte equality.
    got = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    got_doc = json.loads(got["ResourcePolicy"])
    assert got_doc == policy_doc, (
        f"expected GetModelPackageGroupPolicy to return the attached policy document "
        f"{policy_doc!r}, got {got_doc!r}"
    )

    sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)

    # After deletion the group must no longer report having any resource policy.
    code, message = _error(
        lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    )
    assert code == "ValidationException", (
        f"expected GetModelPackageGroupPolicy on a group with no policy to fail with "
        f"ValidationException, got {code!r}"
    )
    expected = f"Cannot find resource policy for: {group_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    sm.delete_model_package_group(ModelPackageGroupName=group_name)

    code, message = _error(lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name))
    assert code == "ValidationException", (
        f"expected DescribeModelPackageGroup on a deleted group to fail with "
        f"ValidationException, got {code!r}"
    )
    expected = f"ModelPackageGroup {group_arn} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
