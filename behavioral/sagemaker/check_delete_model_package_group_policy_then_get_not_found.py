"""delete-model-package-group-policy-then-get-not-found."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-model-package-group-policy-then-get-not-found"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteModelPackageGroupPolicy removes an attached policy, a subsequent
    GetModelPackageGroupPolicy returns ResourceNotFound -- the deletion's real, observable
    consequence rather than merely a 200 on the delete call itself.
    """
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    group_name = ctx.unique_name("sim2real-mpg-policy-")

    sm.create_model_package_group(ModelPackageGroupName=group_name)
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    account_id = sts.get_caller_identity()["Account"]
    group_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": group_arn,
            }
        ],
    }
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy)
    )

    # Confirm the attach really landed before testing the delete's consequence.
    fetched = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    actual_policy = json.loads(fetched["ResourcePolicy"])
    assert actual_policy == policy, (actual_policy, policy)

    sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)

    code, msg = _error_code_and_message(lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name))
    # Empirically, GetModelPackageGroupPolicy raises ValidationException (not ResourceNotFound)
    # once the resource policy has been removed -- SageMaker treats "no policy attached" as a
    # validation failure on this read path rather than a 404-style not-found.
    assert code == "ValidationException", (code, msg)
    expected_message = f"Cannot find resource policy for: {group_arn}"
    assert msg == expected_message, f"expected {expected_message!r}, got {msg!r}"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
