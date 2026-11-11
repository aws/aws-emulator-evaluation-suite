"""model-package-group-policy-json-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-policy-json-round-trip"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A JSON resource policy on a ModelPackageGroup round-trips through Put/Get and is
    gone after Delete -- a subsequent Get raises ValidationException, not ResourceNotFound."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AddPermModelPackageGroup",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackage",
                "Resource": group_arn,
            }
        ],
    }
    sm.put_model_package_group_policy(ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy_doc))

    fetched = json.loads(sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"])
    assert fetched == policy_doc, f"policy round-trip mismatch: {fetched!r} != {policy_doc!r}"

    sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)

    # GetModelPackageGroupPolicy on a group with no attached policy raises
    # ValidationException ("Cannot find resource policy"), not a 404-style
    # ResourceNotFound -- SageMaker treats "no policy attached" as a validation
    # failure on this read path.
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
