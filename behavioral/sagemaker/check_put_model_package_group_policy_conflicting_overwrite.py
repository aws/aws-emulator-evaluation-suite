"""put-model-package-group-policy-conflicting-overwrite."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-model-package-group-policy-conflicting-overwrite"
GROUP = "concurrency"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing PutModelPackageGroupPolicy calls leave at least one success, every loser refused with
    ValidationException and the exact in-flight message, and a final policy identical to exactly one submitted
    document.
    """
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpg-policyrace-")
    group_arn = sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    ctx.on_cleanup(lambda: _delete_policy_ignore(sm, group_name))

    # The group's own creation is itself asynchronous (Pending/InProgress ->
    # Completed); wait it out first so the race below tests policy-write
    # contention specifically, not incidental "resource not fully created yet"
    # errors on some racers.
    _wait_for_group_completed(sm, group_name, timeout_s=60)

    def _policy_for(nonce: int) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": f"Sim2RealRacer{nonce}",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "sagemaker:DescribeModelPackageGroup",
                        "Resource": group_arn,
                    }
                ],
            }
        )

    racer_count = 6
    policies = [_policy_for(i) for i in range(racer_count)]

    def _put(policy: str):
        sm.put_model_package_group_policy(ModelPackageGroupName=group_name, ResourcePolicy=policy)

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_put, policy) for policy in policies]
        results = []
        for future in futures:
            try:
                future.result()
                results.append(("ok", None))
            except ClientError as exc:
                results.append(("error", exc.response["Error"]))

    successes = [r for r in results if r[0] == "ok"]
    failures = [(r[1]["Code"], r[1]) for r in results if r[0] == "error"]
    failure_codes = sorted({code for code, _ in failures})

    # At least one racer must land: the resource ends up in a well-defined state,
    # never universally rejected.
    assert len(successes) >= 1, f"no racer succeeded; failure codes were {failure_codes}"
    # Real AWS rejects the losing racers of a concurrent PutModelPackageGroupPolicy
    # write with an UNDOCUMENTED ValidationException that names the in-flight policy
    # and the group ARN; the operation's own Smithy model documents only
    # ConflictException, which real AWS does not return here.
    expected_message = (
        "Invalid policy provided : InflightPolicy: There is an existing policy inflight "
        f"for resource: {group_arn}"
    )
    for code, err in failures:
        assert code == "ValidationException", (
            f"unexpected rejection code on a losing racer, want ValidationException, "
            f"got {code}: {err.get('Message')!r}"
        )
        assert err.get("Message") == expected_message, (
            f"unexpected rejection message on a losing racer: {err.get('Message')!r}"
        )

    final_policy = json.loads(sm.get_model_package_group_policy(ModelPackageGroupName=group_name)["ResourcePolicy"])
    matches = [p for p in policies if json.loads(p) == final_policy]
    assert len(matches) == 1, (
        f"final policy matches {len(matches)} of the {racer_count} submitted documents "
        f"(want exactly 1, proving atomicity): {final_policy}"
    )


def _wait_for_group_completed(sm, group_name: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_model_package_group(ModelPackageGroupName=group_name)["ModelPackageGroupStatus"]
        if status == "Completed":
            return
        if status in ("Failed", "DeleteFailed"):
            raise AssertionError(f"model package group entered unexpected status={status}")
        time.sleep(1)
    raise AssertionError(f"model package group never reached Completed, last status={status}")


def _delete_policy_ignore(sm, group_name: str) -> None:
    try:
        sm.delete_model_package_group_policy(ModelPackageGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


