"""model-package-group-policy-concurrent-put-last-writer-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-package-group-policy-concurrent-put-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two racing PutModelPackageGroupPolicy calls (each retrying the InflightPolicy
    ValidationException) leave GetModelPackageGroupPolicy returning exactly one of the two submitted
    documents in full, never a merge.
    """
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    ctx.on_cleanup(
        lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
    )

    policy_a = _policy_doc(account_id, group_arn, "sim2real-policy-a", "sagemaker:DescribeModelPackage")
    policy_b = _policy_doc(account_id, group_arn, "sim2real-policy-b", "sagemaker:ListModelPackages")

    def _put(policy_doc, deadline):
        while True:
            try:
                sm.put_model_package_group_policy(
                    ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy_doc)
                )
                return
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ValidationException" and "InflightPolicy" in err.get(
                    "Message", ""
                ):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.5)
                    continue
                raise

    deadline = time.monotonic() + 30.0
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put, policy_a, deadline), pool.submit(_put, policy_b, deadline)]
        for fut in futures:
            fut.result()

    final_policy = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    candidates = [policy_a, policy_b]
    assert final_policy in candidates, (
        "final policy is neither submitted document in full -- "
        f"got a merged/corrupted state: {final_policy}"
    )


def _policy_doc(account_id: str, group_arn: str, sid: str, action: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": action,
                "Resource": group_arn,
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
