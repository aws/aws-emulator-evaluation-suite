"""model-package-group-policy-invalid-json-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "model-package-group-policy-invalid-json-rejected"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy with malformed JSON is refused with ValidationException "Invalid
    Policy: This policy contains invalid Json" and attaches nothing (Get: "Cannot find resource policy
    for: <arn>"); a well-formed policy put afterwards on the same group reads back exactly.
    """
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    group_name = ctx.unique_name("sim2real-mpg-badjson-")

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    malformed = '{"Version": "2012-10-17", "Statement": [ this is not valid json ] '
    account_id = sts.get_caller_identity()["Account"]
    group_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"

    code, message = _error(
        lambda: sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=malformed
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid Policy: This policy contains invalid Json", message

    # Effect absent: no policy was attached by the rejected call.
    not_found_code, not_found_msg = _error(
        lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    )
    # GetModelPackageGroupPolicy raises ValidationException (not ResourceNotFound) when no
    # policy is attached: SageMaker treats "no policy" as a validation failure on this read path.
    assert not_found_code == "ValidationException", (not_found_code, not_found_msg)
    assert not_found_msg == f"Cannot find resource policy for: {group_arn}", not_found_msg

    # Positive control: a well-formed policy on the very same group still works.
    good_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GoodPolicyAfterBadOne",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": group_arn,
            }
        ],
    }
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(good_policy)
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name))
    fetched = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert fetched == good_policy, f"expected {good_policy!r}, got {fetched!r}"


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
