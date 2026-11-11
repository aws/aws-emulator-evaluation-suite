"""concurrent-put-permission-race-single-revision-winner."""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-permission-race-single-revision-winner"
GROUP = "concurrency"
SERVICES = ["codeguruprofiler"]


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutPermission calls with the same revisionId let exactly one racer win and the others fail
    with ConflictException, GetPolicy returns the winner's revisionId, and a call with that revisionId
    advances it."""
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-cgp-race-")
    token = str(uuid.uuid4())
    cgp.create_profiling_group(profilingGroupName=name, clientToken=token)
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    account_id = sts.get_caller_identity()["Account"]
    base_principal = f"arn:aws:iam::{account_id}:root"
    baseline = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[base_principal]
    )
    base_rev = baseline["revisionId"]
    # A real, currently-existing IAM principal (the caller's own ARN) so the
    # service's principal-existence validation accepts every racer's request.
    extra_principal = sts.get_caller_identity()["Arn"]

    n_racers = 5

    def racer(i):
        try:
            resp = cgp.put_permission(
                profilingGroupName=name,
                actionGroup="agentPermissions",
                principals=[base_principal, extra_principal],
                revisionId=base_rev,
            )
            return ("ok", resp["revisionId"])
        except ClientError as exc:
            return ("error", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(racer, range(n_racers)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {successes}"
    assert len(failures) == n_racers - 1, f"expected {n_racers - 1} losers, got {results}"
    winning_rev = successes[0][1]
    # AWS answers a lost revision race with either of two exact wordings.
    outdated = "Trying to update an outdated revision, please retry!"
    superseded = f"Policy has been updated since the revision: {base_rev}, new RevisionId: {winning_rev}"
    for _, (code, message) in failures:
        assert code == "ConflictException" and message in (outdated, superseded), failures
    final = cgp.get_policy(profilingGroupName=name)
    assert final["revisionId"] == winning_rev, (
        f"expected the winning racer's revisionId {winning_rev!r} to be current, "
        f"got {final['revisionId']!r}"
    )

    # Restore leg: the ConflictException the losers saw was specific to their stale
    # revisionId, not a permanent block -- the identical call succeeds once it targets the
    # current revision.
    restored = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[base_principal, extra_principal],
        revisionId=winning_rev,
    )
    assert restored["revisionId"] != winning_rev, (
        f"expected put_permission with the current revisionId {winning_rev!r} to advance "
        f"the revision, got {restored['revisionId']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
