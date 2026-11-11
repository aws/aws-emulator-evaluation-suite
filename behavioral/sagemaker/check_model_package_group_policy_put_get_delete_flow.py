"""model-package-group-policy-put-get-delete-flow."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "model-package-group-policy-put-get-delete-flow"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy is immediately visible via Get, and after
    DeleteModelPackageGroupPolicy, Get raises the specific ValidationException
    SageMaker uses to report "no resource policy attached" on this read path."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-sm-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddPermission",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackage",
                "Resource": group_arn,
            }
        ],
    }
    put_resp = sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy)
    )
    assert put_resp["ModelPackageGroupArn"] == group_arn, (
        f"expected {group_arn!r}, got {put_resp['ModelPackageGroupArn']!r}"
    )

    get_resp = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    fetched_policy = json.loads(get_resp["ResourcePolicy"])
    assert fetched_policy["Statement"][0]["Sid"] == "AddPermission", (
        f"expected Sid 'AddPermission', got {fetched_policy['Statement'][0].get('Sid')!r}"
    )
    assert fetched_policy["Statement"][0]["Action"] == "sagemaker:DescribeModelPackage", (
        f"expected Action 'sagemaker:DescribeModelPackage', "
        f"got {fetched_policy['Statement'][0].get('Action')!r}"
    )

    sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)

    code, msg = _error_code(lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException, got code={code!r} msg={msg!r}"
    assert msg == f"Cannot find resource policy for: {group_arn}", msg


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
