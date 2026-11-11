"""model-package-group-policy-put-get-delete-consistency."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "model-package-group-policy-put-get-delete-consistency"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutModelPackageGroupPolicy -> GetModelPackageGroupPolicy round-trips the exact
    document, and DeleteModelPackageGroupPolicy makes a subsequent Get fail."""
    sm = ctx.client("sagemaker")
    group_name = ctx.unique_name("sim2real-mpg-")

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        ModelPackageGroupDescription="sim2real behavioral check",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_doc = {
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
        ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy_doc)
    )

    got = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    round_tripped = json.loads(got["ResourcePolicy"])
    assert round_tripped == policy_doc, (
        f"GetModelPackageGroupPolicy returned a different document: {round_tripped!r} "
        f"!= {policy_doc!r}"
    )

    # PutModelPackageGroupPolicy leaves the resource with a brief "inflight policy
    # change" state; DeleteModelPackageGroupPolicy issued immediately after can be
    # rejected with ValidationException/InflightPolicy until that settles. Retry the
    # delete on that specific transient condition with a bounded backoff.
    _retry_until_not_inflight(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name))

    code, message = _error(lambda: sm.get_model_package_group_policy(ModelPackageGroupName=group_name))
    assert code == "ValidationException", (
        f"expected ValidationException after policy deletion, got {code!r}"
    )
    group_arn = f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}"
    assert message == f"Cannot find resource policy for: {group_arn}", message


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_until_not_inflight(fn, *, timeout_s=60.0, interval_s=3.0):
    from botocore.exceptions import ClientError

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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
