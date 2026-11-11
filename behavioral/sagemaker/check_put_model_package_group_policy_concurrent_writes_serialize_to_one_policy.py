"""put-model-package-group-policy-concurrent-writes-serialize-to-one-policy."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-concurrent-writes-serialize-to-one-policy"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutModelPackageGroupPolicy calls (each retrying the InflightPolicy
    ValidationException) all succeed, and the final policy holds exactly one statement whose
    Sid is one of the submitted ones.
    """
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    n = 5
    candidates = [_make_policy(account_id, group_arn, i) for i in range(n)]

    def _put(policy):
        deadline = time.monotonic() + 30.0
        while True:
            try:
                sm.put_model_package_group_policy(
                    ModelPackageGroupName=group_name, ResourcePolicy=json.dumps(policy)
                )
                return True
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

    with ThreadPoolExecutor(max_workers=n) as pool:
        results = list(pool.map(_put, candidates))
    assert all(results), "every racer's PutModelPackageGroupPolicy should eventually succeed"

    final_raw = sm.get_model_package_group_policy(ModelPackageGroupName=group_name)[
        "ResourcePolicy"
    ]
    final = json.loads(final_raw)

    # AWS may canonicalize the policy document on write (e.g. normalize the
    # Principal into a full ARN), so compare on the untouched, unique-per-
    # racer Sid rather than deep dict equality -- what matters is that the
    # final state is EXACTLY one whole racer's write, never a mixture.
    final_sids = [stmt.get("Sid") for stmt in final.get("Statement", [])]
    assert len(final_sids) == 1, (
        f"final policy must contain exactly one Statement, not a merged/"
        f"corrupted mixture; final={final}"
    )
    candidate_sids = {c["Statement"][0]["Sid"] for c in candidates}
    assert final_sids[0] in candidate_sids, (
        f"final policy Sid {final_sids[0]!r} must be exactly one of the "
        f"submitted racers' Sids {candidate_sids}, not a corrupted/unknown value"
    )


def _make_policy(account_id, group_arn, index):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": f"sim2realRacer{index}",
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "sagemaker:DescribeModelPackage",
                "Resource": group_arn,
            }
        ],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

