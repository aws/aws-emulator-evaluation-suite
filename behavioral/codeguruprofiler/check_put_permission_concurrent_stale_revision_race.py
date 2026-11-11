"""put-permission-concurrent-stale-revision-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-permission-concurrent-stale-revision-race"
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
    role_name = ctx.unique_name(f"sim2real-cgp-stale-{suffix}-")
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _retry_while_principal_unrecognized(fn, timeout_s=30.0, interval_s=2.0):
    """Retry fn() while codeguru-profiler still reports a just-created principal ARN as
    unrecognized -- IAM role creation is not instantly visible to every downstream
    service's principal-existence check. Anything else (success, or a ConflictException)
    is returned/raised as-is."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            error = err.response["Error"]
            if (
                error["Code"] == "ValidationException"
                and "Principal" in error.get("Message", "")
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Once an update advances the policy, every concurrent PutPermission against the stale revisionId fails with
    ConflictException and the policy stays at the newer revision, while a PutPermission against the current
    revision succeeds.
    """
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-cgp-stale-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    base_principal = f"arn:aws:iam::{account_id}:root"
    rev1 = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[base_principal]
    )["revisionId"]

    # Positive control, and the update that makes rev1 stale: an independent PutPermission
    # against rev1 succeeds and advances the policy to rev2 BEFORE any racer runs.
    caller_arn = sts.get_caller_identity()["Arn"]
    rev2_resp = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[base_principal, caller_arn],
        revisionId=rev1,
    )
    rev2 = rev2_resp["revisionId"]
    assert rev2 != rev1, "the advancing update must itself produce a new revisionId"
    ctx.on_cleanup(
        lambda: cgp.remove_permission(
            profilingGroupName=name,
            actionGroup="agentPermissions",
            revisionId=cgp.get_policy(profilingGroupName=name)["revisionId"],
        )
    )

    racer_count = 4
    # Distinct, real, currently-existing IAM roles so the service's principal-existence
    # validation accepts every racer -- each racer's principal is unique so a wrongly
    # accepted racer would be individually detectable in the final policy.
    racer_principals = [_create_role(ctx, iam, i) for i in range(racer_count)]

    def _racer(principal: str):
        # A stale revisionId is rejected before principal existence is even checked (this
        # is observable: an as-yet-unrecognized freshly created role still gets
        # ConflictException here, never ValidationException), so no retry is needed on
        # this leg -- every racer's outcome is returned as-is.
        try:
            resp = cgp.put_permission(
                profilingGroupName=name,
                actionGroup="agentPermissions",
                principals=[base_principal, principal],
                revisionId=rev1,
            )
            return ("ok", resp["revisionId"])
        except ClientError as err:
            return ("error", (err.response["Error"]["Code"], err.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_racer, racer_principals))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 0, f"a stale revisionId must never win a race, got {results}"
    assert len(failures) == racer_count, f"expected {racer_count} conflicts, got {results}"
    # AWS answers a stale revisionId with either of two exact wordings.
    outdated = "Trying to update an outdated revision, please retry!"
    superseded = f"Policy has been updated since the revision: {rev1}, new RevisionId: {rev2}"
    for _status, (code, message) in failures:
        assert code == "ConflictException" and message in (outdated, superseded), failures

    # Effect absent: the policy is still exactly rev2's content; no racer principal landed.
    unchanged = cgp.get_policy(profilingGroupName=name)
    assert unchanged["revisionId"] == rev2, "a losing stale-revision racer must not advance the policy"
    for principal in racer_principals:
        assert principal not in unchanged["policy"], f"{principal} must not appear in the untouched policy"

    # Restore beat: PutPermission against the CURRENT (correct) revision still succeeds.
    # Unlike the stale-revision racers above, this call's revisionId IS current, so it
    # falls through to real principal-existence validation -- which the freshly created
    # role may not have propagated to yet.
    rev3_resp = _retry_while_principal_unrecognized(
        lambda: cgp.put_permission(
            profilingGroupName=name,
            actionGroup="agentPermissions",
            principals=[base_principal, caller_arn, racer_principals[0]],
            revisionId=rev2,
        )
    )
    assert rev3_resp["revisionId"] != rev2, "a call against the current revision must still advance it"
    assert racer_principals[0] in rev3_resp["policy"], "the correctly-revisioned update must take effect"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
