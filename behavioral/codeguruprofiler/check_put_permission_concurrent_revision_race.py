"""put-permission-concurrent-revision-race."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-permission-concurrent-revision-race"
GROUP = "concurrency"
SERVICES = ["codeguruprofiler"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent PutPermission calls against the same revisionId let exactly one racer win and the others fail
    with ConflictException, and GetPolicy then returns the winner's revisionId.
    """
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-")
    account_id = sts.get_caller_identity()["Account"]

    cgp.create_profiling_group(
        profilingGroupName=name,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    base_principal = f"arn:aws:iam::{account_id}:root"
    base_revision = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[base_principal]
    )["revisionId"]

    n_racers = 6

    def _racer(i: int):
        try:
            resp = cgp.put_permission(
                profilingGroupName=name,
                actionGroup="agentPermissions",
                principals=[base_principal],
                revisionId=base_revision,
            )
            return ("OK", resp["revisionId"])
        except ClientError as err:
            return (err.response["Error"]["Code"], None)

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_racer, range(n_racers)))

    successes = [r for r in results if r[0] == "OK"]
    conflicts = [r for r in results if r[0] == "ConflictException"]
    assert len(successes) == 1, f"expected exactly 1 winner, got {results}"
    assert len(conflicts) == n_racers - 1, f"expected {n_racers - 1} conflicts, got {results}"

    winning_revision = successes[0][1]
    final = cgp.get_policy(profilingGroupName=name)
    assert final["revisionId"] == winning_revision, (
        f"expected the destination's revisionId to be the race winner's own "
        f"{winning_revision!r}, got {final['revisionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
