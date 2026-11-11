"""concurrent-put-model-package-group-policy-last-writer-wins."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-model-package-group-policy-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutModelPackageGroupPolicy calls on the same group resolve to exactly
    one of the two payloads, never a corrupted merge of both."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-mpg-")
    resp = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    group_arn = resp["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _cleanup_group(ctx, group_name))

    policy_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realPolicyA",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackage",
                "Resource": group_arn,
            }
        ],
    }
    policy_b = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realPolicyB",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:ListModelPackages",
                "Resource": group_arn,
            }
        ],
    }

    def _put(policy: dict) -> None:
        sm.put_model_package_group_policy(
            ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy)
        )

    errors = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put, policy_a), pool.submit(_put, policy_b)]
        for f in futures:
            try:
                f.result()
            except ClientError as exc:
                errors.append(exc)

    assert len(errors) < 2, f"both concurrent PutModelPackageGroupPolicy calls failed: {errors}"

    final_raw = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    final = json.loads(final_raw)
    sids = {stmt["Sid"] for stmt in final.get("Statement", [])}

    assert final in (policy_a, policy_b), (
        f"resource policy is neither input payload verbatim (possible corruption): {final}"
    )
    assert sids in ({"sim2realPolicyA"}, {"sim2realPolicyB"}), f"corrupted merge detected: {sids}"


# ===== helpers =====
def _cleanup_group(ctx, group_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    try:
        sm.delete_model_package_group(ModelPackageGroupName=group_name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "ResourceNotFound":
            return
        if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
