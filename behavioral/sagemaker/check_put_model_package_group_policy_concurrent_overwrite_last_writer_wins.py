"""put-model-package-group-policy-concurrent-overwrite-last-writer-wins."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-model-package-group-policy-concurrent-overwrite-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two racing PutModelPackageGroupPolicy calls with different bodies leave exactly one of the
    two whole documents in GetModelPackageGroupPolicy, never a merge of both statements."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    group_name = ctx.unique_name("sim2real-behav-mpg-")

    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)))

    def _policy(sid):
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": sid,
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "sagemaker:DescribeModelPackage",
                        "Resource": f"arn:aws:sagemaker:{ctx.region}:{account_id}:model-package-group/{group_name}",
                    }
                ],
            }
        )

    policy_a = _policy("sim2realBehavPolicyA")
    policy_b = _policy("sim2realBehavPolicyB")

    # Concurrent puts on one resource are serialized: the race loser gets a transient
    # ValidationException "InflightPolicy: There is an existing policy inflight ...".
    def _put_with_retry(policy, retries=8, delay=1.5):
        from botocore.exceptions import ClientError

        last_exc = None
        for attempt in range(retries):
            try:
                sm.put_model_package_group_policy(ModelPackageGroupName=group_name, ResourcePolicy=policy)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                msg = str(exc)
                if code == "ValidationException" and "InflightPolicy" in msg and attempt < retries - 1:
                    last_exc = exc
                    time.sleep(delay)
                    continue
                raise
        raise last_exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put_with_retry, policy_a), pool.submit(_put_with_retry, policy_b)]
        for fut in futures:
            fut.result()

    final = json.loads(sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"])
    statements = final["Statement"]
    assert len(statements) == 1, f"expected exactly one statement (no merge), got {len(statements)}: {final!r}"
    sid = statements[0]["Sid"]
    assert sid in {"sim2realBehavPolicyA", "sim2realBehavPolicyB"}, f"unexpected final policy Sid: {sid!r}"
    assert final == json.loads(policy_a) or final == json.loads(policy_b), (
        "final policy is neither of the two written documents verbatim -- looks corrupted"
    )


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

