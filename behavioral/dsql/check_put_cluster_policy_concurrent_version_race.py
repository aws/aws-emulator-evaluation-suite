"""put-cluster-policy-concurrent-version-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-cluster-policy-concurrent-version-race"
GROUP = "concurrency"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When N racing PutClusterPolicy calls all present the SAME expectedPolicyVersion baseline,
    optimistic concurrency guarantees exactly one wins (produces a new policyVersion) and every
    other racer fails with ConflictException -- never two winners, never zero."""
    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    created = dsql.create_cluster(deletionProtectionEnabled=False, tags={"sim2real-check": CHECK})
    identifier = created["identifier"]
    arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))
    _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)

    base_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "dsql:DbConnect", "Resource": arn,
        }],
    }
    base_version = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(base_policy))["policyVersion"]

    racer_count = 6

    def _racer(i):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": f"dsql:DbConnect", "Resource": arn, "Sid": f"racer{i}",
            }],
        }
        try:
            resp = dsql.put_cluster_policy(identifier=identifier, policy=json.dumps(policy), expectedPolicyVersion=base_version)
            return ("won", resp["policyVersion"], None, i)
        except Exception as err:
            from botocore.exceptions import ClientError
            if isinstance(err, ClientError):
                return ("lost", err.response["Error"]["Code"], err.response["Error"].get("Message"), i)
            raise

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        results = [f.result() for f in as_completed(futures)]

    winners = [r for r in results if r[0] == "won"]
    losers = [r for r in results if r[0] == "lost"]

    assert len(winners) == 1, f"expected exactly one winner of the optimistic-concurrency race, got {winners}"
    assert len(losers) == racer_count - 1, f"expected {racer_count - 1} losers, got {len(losers)}: {results}"
    assert all(code == "ConflictException" for _, code, _, _ in losers), losers
    expected_message = (
        f"Aurora DSQL can't find policy version {base_version} for resource {identifier}. "
        "Verify that the policy exists and that the version is correct."
    )
    assert all(message == expected_message for _, _, message, _ in losers), losers

    final = dsql.get_cluster_policy(identifier=identifier)
    assert final["policyVersion"] == winners[0][1], (
        f"final policyVersion {final['policyVersion']!r} does not match race winner's {winners[0][1]!r}"
    )
    winning_sid = json.loads(final["policy"])["Statement"][0]["Sid"]
    assert winning_sid == f"racer{winners[0][3]}", (
        f"final policy content Sid {winning_sid!r} does not match declared winner racer{winners[0][3]}"
    )


def _wait_for_status(dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
