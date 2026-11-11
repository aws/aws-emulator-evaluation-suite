"""put-model-package-group-policy-concurrent-last-writer-wins."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-concurrent-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutModelPackageGroupPolicy calls with different documents leave a final policy
    equal to exactly one of them, with a single statement, never a merge.
    """
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-behav-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    policy_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SimParityPolicyA",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:DescribeModelPackageGroup",
                "Resource": group_arn,
            }
        ],
    }
    policy_b = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SimParityPolicyB",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sagemaker:ListModelPackages",
                "Resource": group_arn,
            }
        ],
    }

    barrier = threading.Barrier(2)

    def _put(policy: dict) -> None:
        barrier.wait()
        # Real SageMaker holds an optimistic lock on a model package group's resource
        # policy: the racer that lands while the other write is still in flight gets a
        # transient ValidationException("...InflightPolicy...") rather than a merge.
        # Retry only that specific error so the race resolves to last-writer-wins
        # rather than a spurious failure on the loser.
        deadline = time.monotonic() + 30.0
        while True:
            try:
                sm.put_model_package_group_policy(
                    ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy)
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

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put, policy_a), pool.submit(_put, policy_b)]
        for f in futures:
            f.result()

    final = json.loads(
        sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"]
    )
    assert final in (policy_a, policy_b), f"final policy matches neither submitted document: {final}"
    assert len(final["Statement"]) == 1, f"final policy shows signs of merge/corruption: {final}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
