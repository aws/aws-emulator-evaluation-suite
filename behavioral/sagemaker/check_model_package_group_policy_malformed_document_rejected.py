"""model-package-group-policy-malformed-document-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "model-package-group-policy-malformed-document-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy with a syntactically invalid JSON document is rejected
    with ValidationException, the previously-stored valid policy is left untouched, and
    a subsequent well-formed Put still succeeds (positive control)."""
    sm = ctx.client("sagemaker")
    group_name = ctx.unique_name("sim2real-mpg-badpolicy-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    good_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2real-allow-describe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}",
            }
        ],
    }
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(good_policy)
    )
    ctx.on_cleanup(lambda: _delete_policy_when_settled(sm, group_name))

    # Break exactly one thing: the ResourcePolicy body is not valid JSON.
    malformed = '{"Version": "2012-10-17", "Statement": [ this is not valid json'
    code, message = _error(
        lambda: sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=malformed
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid Policy: This policy contains invalid Json", message

    # Effect absent: the previously-stored valid policy must still be exactly there.
    current = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert current == good_policy, (
        f"malformed Put must not overwrite the stored policy; got {current!r}"
    )

    # Positive control: a well-formed Put still works after the rejected attempt.
    updated_policy = dict(good_policy)
    updated_policy["Statement"] = good_policy["Statement"] + [
        {
            "Sid": "sim2real-allow-list",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sagemaker:ListModelPackages",
            "Resource": f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}",
        }
    ]
    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(updated_policy)
    )
    after_good_put = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert after_good_put == updated_policy, (
        f"expected the well-formed Put to persist, got {after_good_put!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_policy_when_settled(sm, group_name, timeout_s=60.0, interval_s=3.0):
    """Teardown: DeleteModelPackageGroupPolicy is refused while a policy change is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
            return
        except ClientError as exc:
            if "InflightPolicy" not in exc.response["Error"].get("Message", ""):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
