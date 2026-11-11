"""put-model-package-group-policy-invalid-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-invalid-policy-rejected"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy refuses a policy with an unknown key with ValidationException "Invalid
    Policy: Unknown field NotAValidPolicyKey" and attaches nothing (Get: "Cannot find resource policy
    for: <arn>"); a well-formed policy put afterwards reads back with its Sid.
    """
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-sm-mpg-bad-")
    group_arn = sm.create_model_package_group(ModelPackageGroupName=group_name)[
        "ModelPackageGroupArn"
    ]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    malformed_policy = json.dumps({"NotAValidPolicyKey": "nonsense", "Statement": "not-a-list"})
    code, message = _error(
        lambda: sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=malformed_policy
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid Policy: Unknown field NotAValidPolicyKey", message

    # Effect (a): no policy was persisted by the rejected call. GetModelPackageGroupPolicy on a
    # group with no attached policy reports this as ValidationException ("Cannot find resource
    # policy for: <arn>"), not a not-found code.
    get_code, get_message = _error(
        lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    )
    assert get_code == "ValidationException", f"expected ValidationException, got {get_code!r}"
    assert get_message == f"Cannot find resource policy for: {group_arn}", get_message

    # Effect (c): a positive control -- a well-formed policy on the SAME group -- works.
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackage",
                "Resource": group_arn,
            }
        ],
    }
    put_resp = sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(valid_policy)
    )
    assert put_resp["ModelPackageGroupArn"] == group_arn, (
        f"expected {group_arn!r}, got {put_resp['ModelPackageGroupArn']!r}"
    )
    fetched = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert fetched["Statement"][0]["Sid"] == "AllowDescribe", (
        f"expected Sid 'AllowDescribe', got {fetched['Statement'][0].get('Sid')!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
