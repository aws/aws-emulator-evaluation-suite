"""model-package-group-policy-concurrent-put-last-write-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-policy-concurrent-put-last-write-wins"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutModelPackageGroupPolicy calls on one group (each retrying the InflightPolicy
    ValidationException) leave GetModelPackageGroupPolicy returning exactly one submitted document with
    one statement, never a merge of both.
    """
    sm = ctx.client("sagemaker")
    group_name = ctx.unique_name("sim2real-behav-mpg-")
    group_arn = sm.create_model_package_group(ModelPackageGroupName=group_name)[
        "ModelPackageGroupArn"
    ]
    ctx.on_cleanup(lambda: _delete_group_and_policy(ctx, group_name))

    account = ctx.client("sts").get_caller_identity()["Account"]
    principal = {"AWS": f"arn:aws:iam::{account}:root"}
    policy_a = _policy_doc(principal, group_arn, "sagemaker:DescribeModelPackage", "AllowDescribeA")
    policy_b = _policy_doc(principal, group_arn, "sagemaker:ListModelPackages", "AllowListB")

    def put_a():
        return sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy_a)
        )

    def put_b():
        return sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy_b)
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put_with_retry, put_a), pool.submit(_put_with_retry, put_b)]
        outcomes = []
        for fut in futures:
            try:
                fut.result()
                outcomes.append("ok")
            except ClientError as exc:
                outcomes.append(exc.response["Error"]["Code"])

    # Both racers retry through any transient InflightPolicy rejection, so
    # both are expected to eventually land; only an unretryable error (a
    # different code, or InflightPolicy surviving every retry) counts as a
    # genuine loss here.
    assert "ok" in outcomes, (
        f"both concurrent PutModelPackageGroupPolicy calls failed even after retrying "
        f"transient InflightPolicy contention: {outcomes}"
    )

    resp = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)
    final_policy = json.loads(resp["ResourcePolicy"])

    assert final_policy in (policy_a, policy_b), (
        "GetModelPackageGroupPolicy returned a document that matches neither "
        f"submitted policy verbatim (looks merged/corrupted): {final_policy}"
    )
    assert len(final_policy["Statement"]) == 1, (
        f"resulting policy has {len(final_policy['Statement'])} statements - "
        "the two concurrent writes were merged instead of one overwriting the other"
    )


def _put_with_retry(fn, retries=8, delay=1.5):
    """Retry fn() while it fails with the transient InflightPolicy optimistic-lock
    rejection; any other error propagates immediately."""
    last_exc = None
    for attempt in range(retries):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ValidationException" and "InflightPolicy" in str(exc) and attempt < retries - 1:
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    raise last_exc


def _policy_doc(principal, group_arn, action, sid):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": principal,
                "Action": action,
                "Resource": group_arn,
            }
        ],
    }


def _delete_group_and_policy(ctx, group_name):
    sm = ctx.client("sagemaker")
    try:
        sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    sm.delete_model_package_group(ModelPackageGroupName=group_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
