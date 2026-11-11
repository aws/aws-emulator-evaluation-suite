"""put-model-package-group-policy-concurrent-overwrite."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-concurrent-overwrite"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent PutModelPackageGroupPolicy calls resolve deterministically to a
    single, uncorrupted last-writer-wins policy document -- never a byte-interleaved
    hybrid of the two documents."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-")
    created = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    group_arn = created["ModelPackageGroupArn"]

    def _cleanup():
        try:
            sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise
        sm.delete_model_package_group(ModelPackageGroupName=group_name)

    ctx.on_cleanup(_cleanup)

    policy_a = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PolicyA",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sagemaker:DescribeModelPackage"],
                "Resource": group_arn,
            }
        ],
    }
    policy_b = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PolicyB",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["sagemaker:DescribeModelPackage", "sagemaker:ListModelPackages"],
                "Resource": group_arn,
            }
        ],
    }

    def _put(policy: dict, timeout_s: float = 30.0) -> dict:
        # Real SageMaker holds an optimistic lock on the group's resource policy: the
        # racer that lands second while the first write is still in flight gets a
        # transient ValidationException("...InflightPolicy...") rather than a merge.
        # Retry that specific error so the race resolves to last-writer-wins instead
        # of a spurious check failure.
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                return sm.put_model_package_group_policy(
                    ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy)
                )
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
        results = [f.result(timeout=30) for f in futures]

    for res in results:
        assert res["ModelPackageGroupArn"] == group_arn

    parsed = _poll_stable_policy(ctx, group_name, timeout_s=20.0)

    matches_a = parsed == policy_a
    matches_b = parsed == policy_b
    assert matches_a or matches_b, (
        f"stored policy is neither document verbatim (possible interleaved corruption): {parsed}"
    )
    assert matches_a != matches_b, "stored policy unexpectedly equals both documents"


def _poll_stable_policy(ctx, group_name: str, timeout_s: float = 20.0) -> dict:
    """Poll GetModelPackageGroupPolicy until two consecutive reads agree, then return
    the parsed JSON document (guards against reading mid-write on an eventually
    consistent backend)."""
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    previous = None
    while time.monotonic() < deadline:
        raw = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)[
            "ResourcePolicy"
        ]
        current = json.loads(raw)
        if previous is not None and previous == current:
            return current
        previous = current
        time.sleep(0.5)
    raise AssertionError("policy document never stabilized within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
