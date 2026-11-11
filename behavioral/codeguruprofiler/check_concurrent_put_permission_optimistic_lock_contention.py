"""concurrent-put-permission-optimistic-lock-contention."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-permission-optimistic-lock-contention"
GROUP = "concurrency"
SERVICES = ["codeguruprofiler"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codeguru-profiler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _create_role(ctx, iam, suffix):
    role_name = ctx.unique_name(f"sim2real-behav-race-{suffix}-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutPermission calls against the same revisionId let exactly one racer win; the others fail with
    ConflictException, and the final policy holds the winner's revision and principal only.
    """
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
        tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    base_principal = f"arn:aws:iam::{account_id}:root"
    base_revision = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[base_principal]
    )["revisionId"]
    ctx.on_cleanup(
        lambda: cgp.remove_permission(
            profilingGroupName=name,
            actionGroup="agentPermissions",
            revisionId=cgp.get_policy(profilingGroupName=name)["revisionId"],
        )
    )

    racer_count = 6
    # Distinct, real, currently-existing IAM roles (freshly created for this
    # check) so the service's principal-existence validation accepts every
    # racer, and each racer's principal is unique for the loser-absence check.
    racer_principals = [_create_role(ctx, iam, i) for i in range(racer_count)]

    def racer(principal: str):
        # Retry on the transient "principal not yet recognized" ValidationException
        # that can follow immediately after IAM role creation (cross-service
        # propagation lag) -- everything else (success, or the expected
        # ConflictException once another racer wins) is returned/raised as-is.
        # Because every racer submits against the SAME base_revision, a retried
        # racer still correctly loses to whichever racer's write landed first.
        deadline = time.monotonic() + 30.0
        while True:
            try:
                return cgp.put_permission(
                    profilingGroupName=name,
                    actionGroup="agentPermissions",
                    principals=[base_principal, principal],
                    revisionId=base_revision,
                )
            except ClientError as err:
                error = err.response["Error"]
                if (
                    error["Code"] == "ValidationException"
                    and "Principal" in error.get("Message", "")
                    and time.monotonic() < deadline
                ):
                    time.sleep(2.0)
                    continue
                raise

    results = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = {pool.submit(racer, p): p for p in racer_principals}
        for future in as_completed(futures):
            principal = futures[future]
            try:
                resp = future.result()
                results.append((principal, "ok", resp["revisionId"]))
            except ClientError as err:
                results.append((principal, "error", (err.response["Error"]["Code"],
                                                     err.response["Error"].get("Message"))))

    successes = [r for r in results if r[1] == "ok"]
    failures = [r for r in results if r[1] == "error"]

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    winner_principal, _status, winner_revision = successes[0]
    # AWS answers a lost revision race with either of two exact wordings.
    outdated = "Trying to update an outdated revision, please retry!"
    superseded = f"Policy has been updated since the revision: {base_revision}, new RevisionId: {winner_revision}"
    for _principal, _status, (code, message) in failures:
        assert code == "ConflictException" and message in (outdated, superseded), (
            f"expected every loser to fail with ConflictException {outdated!r} or {superseded!r}, "
            f"got {failures}"
        )

    final = cgp.get_policy(profilingGroupName=name)
    assert final["revisionId"] == winner_revision, (
        f"expected final revisionId {winner_revision!r}, got {final['revisionId']!r}"
    )
    assert winner_principal in final["policy"], (
        f"expected winner principal {winner_principal!r} in final policy {final['policy']!r}"
    )
    for principal, _status, _detail in failures:
        assert principal not in final["policy"], (
            f"lost update: loser principal {principal!r} unexpectedly present in "
            f"final policy {final['policy']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
