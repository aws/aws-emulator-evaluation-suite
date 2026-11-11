"""get-model-package-group-policy-missing."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-model-package-group-policy-missing"
GROUP = 'error-semantics'
SERVICES = ['sagemaker']

def _create_model_package_group(ctx, name=None):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-mpg-")
    arn = sm.create_model_package_group(
        ModelPackageGroupName=name,
        ModelPackageGroupDescription="behav registry group",
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=name))
    return name, arn


def _error_code(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetModelPackageGroupPolicy on a group with no policy is refused with ValidationException
    "Cannot find resource policy for: <group arn>"; after PutModelPackageGroupPolicy the same read
    returns the exact policy document.
    """
    sm = ctx.client("sagemaker")
    name, group_arn = _create_model_package_group(ctx)

    err = _error_code(lambda: sm.get_model_package_group_policy(ModelPackageGroupName=name))
    assert err.get("Code") == "ValidationException", (
        f"expected ValidationException for a group with no attached policy, got {err!r}"
    )
    assert err.get("Message") == f"Cannot find resource policy for: {group_arn}", (
        f"unexpected GetModelPackageGroupPolicy message: {err.get('Message')!r}"
    )

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SelfDescribe",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{group_arn.split(':')[4]}:root"},
                    "Action": "sagemaker:DescribeModelPackageGroup",
                    "Resource": group_arn,
                }
            ],
        },
        separators=(",", ":"),
    )
    put_resp = sm.put_model_package_group_policy(
        ModelPackageGroupName=name, ResourcePolicy=policy_doc
    )
    assert put_resp["ModelPackageGroupArn"] == group_arn, put_resp

    fetched = sm.get_model_package_group_policy(ModelPackageGroupName=name)
    assert fetched["ResourcePolicy"] == policy_doc, (
        f"expected the attached policy to read back byte-identical, got {fetched['ResourcePolicy']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
