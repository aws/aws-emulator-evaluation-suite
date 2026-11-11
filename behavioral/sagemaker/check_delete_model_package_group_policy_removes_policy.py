"""delete-model-package-group-policy-removes-policy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-model-package-group-policy-removes-policy"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteModelPackageGroupPolicy, GetModelPackageGroupPolicy raises ValidationException
    "Cannot find resource policy" rather than serving the deleted policy, because SageMaker reports
    a missing policy as a validation failure, not a 404-style not-found."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-mpg-delpol-")

    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _delete_group_quiet(sm, group_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootDescribe",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": group_arn,
            }
        ],
    }

    sm.put_model_package_group_policy(
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy_doc)
    )

    # Confirm the policy is actually in effect before deleting it. SageMaker
    # re-serializes the document (no whitespace), so compare parsed JSON, not bytes.
    before = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    before_doc = json.loads(before["ResourcePolicy"])
    assert before_doc == policy_doc, (
        f"expected the just-put policy back, got {before_doc!r}"
    )

    # PutModelPackageGroupPolicy leaves the resource in a brief "inflight policy
    # change" state; a delete issued immediately after can be rejected with
    # ValidationException/InflightPolicy until that settles. Retry the delete on
    # that specific transient condition with a bounded backoff.
    _retry_until_not_inflight(
        lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
    )

    code, message = _error_code_and_message(
        lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_message = f"Cannot find resource policy for: {group_arn}"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


# ===== helpers =====
def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _retry_until_not_inflight(fn, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "InflightPolicy" in message:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"policy change never left in-flight state within {timeout_s}s: {last_exc!r}")


def _delete_group_quiet(sm, name: str) -> None:
    try:
        _retry_until_not_inflight(lambda: sm.delete_model_package_group(ModelPackageGroupName=name))
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
