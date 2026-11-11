"""model-package-group-policy-put-get-delete-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-policy-put-get-delete-round-trip"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A policy written via PutModelPackageGroupPolicy round-trips byte-for-byte through
    GetModelPackageGroupPolicy, and is gone (ValidationException) after DeleteModelPackageGroupPolicy."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    group_arn = sm.describe_model_package_group(ModelPackageGroupName=group_name)["ModelPackageGroupArn"]

    # Deterministic key ordering + explicit separators so the exact string we send is
    # what we compare against on read-back.
    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AddPermModelPackageGroup",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": ["sagemaker:DescribeModelPackage", "sagemaker:ListModelPackages"],
                    "Resource": group_arn,
                }
            ],
        },
        separators=(",", ":"),
    )

    sm.put_model_package_group_policy(ModelPackageGroupName=group_name, ResourcePolicy=policy_doc)

    fetched = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    assert fetched == policy_doc, f"policy round-trip mismatch: {fetched!r} != {policy_doc!r}"

    sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)

    # GetModelPackageGroupPolicy raises ValidationException (not
    # ResourceNotFound) once the resource policy has been removed -- SageMaker treats
    # "no policy attached" as a validation failure on this read path rather than a
    # 404-style not-found.
    code, message = _error(lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException after policy deletion, got {code!r}"
    assert message == f"Cannot find resource policy for: {group_arn}", message


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
