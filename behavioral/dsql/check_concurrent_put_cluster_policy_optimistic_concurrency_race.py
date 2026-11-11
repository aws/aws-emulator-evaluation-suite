"""concurrent-put-cluster-policy-optimistic-concurrency-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-cluster-policy-optimistic-concurrency-race"
GROUP = "concurrency"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When several racers call PutClusterPolicy against the same expectedPolicyVersion, exactly one wins
    and every other racer gets ConditionalCheckFailedException-style ConflictException; the final policy
    is exactly the winner's."""
    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real-check": "concurrent-put-cluster-policy-optimistic-concurrency-race"},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, identifier))

    def _active_status():
        status = dsql.get_cluster(identifier=identifier)["status"]
        if status == "FAILED":
            raise AssertionError(f"cluster {identifier} entered FAILED while waiting for ACTIVE")
        return status

    _poll_until(_active_status, lambda s: s == "ACTIVE", timeout_s=300.0, interval_s=5.0)

    base_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountConnect",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "dsql:DbConnect",
                "Resource": "*",
            }
        ],
    }
    base_version = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(base_policy))[
        "policyVersion"
    ]

    racer_count = 5
    racer_policies = [
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": f"Racer{i}",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "dsql:DbConnect",
                    "Resource": "*",
                    "Condition": {"StringEquals": {"aws:sim2real-racer": str(i)}},
                }
            ],
        }
        for i in range(racer_count)
    ]

    def _racer(policy_doc):
        try:
            resp = dsql.put_cluster_policy(
                identifier=identifier, policy=json.dumps(policy_doc), expectedPolicyVersion=base_version
            )
            return ("ok", resp["policyVersion"])
        except Exception as exc:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            raise

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, policy) for policy in racer_policies]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, f"expected {racer_count - 1} losers, got {len(failures)}"
    assert all(f[1] == "ConflictException" for f in failures), failures
    expected = (
        f"Aurora DSQL can't find policy version {base_version} for resource {identifier}. "
        "Verify that the policy exists and that the version is correct."
    )
    assert all(f[2] == expected for f in failures), f"expected every loser's message to be {expected!r}: {failures}"

    winning_version = successes[0][1]
    final = dsql.get_cluster_policy(identifier=identifier)
    assert final["policyVersion"] == winning_version, (
        f"the attached policy version must be the sole winner's version {winning_version!r}; "
        f"get_cluster_policy reports {final['policyVersion']!r}"
    )
    winning_sid = json.loads(final["policy"])["Statement"][0]["Sid"]
    assert winning_sid.startswith("Racer"), (
        f"the attached policy document must be one of the racer documents (Sid starting with "
        f"'Racer'); an independent read reports Sid {winning_sid!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
