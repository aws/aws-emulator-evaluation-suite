"""put-permission-stale-revision-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-permission-stale-revision-conflict-rejected"
GROUP = "overly-permissive"
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


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_until_principal_recognized(fn, timeout_s=30.0, interval_s=2.0):
    """Retry fn() while CodeGuru Profiler still reports the (freshly created)
    principal ARN as unrecognized -- IAM role creation is not instantly visible
    to every downstream service's principal-existence check."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] == "ValidationException" and "Principal" in error.get(
                "Message", ""
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"principal never became recognized (last error={last_err})")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutPermission with a superseded revisionId fails with ConflictException and leaves the policy at the newer
    revision, while PutPermission with the current revisionId succeeds and GetPolicy reflects it.
    """
    cgp = ctx.client("codeguruprofiler")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cgp-")
    cgp.create_profiling_group(
        profilingGroupName=name,
        agentOrchestrationConfig={"profilingEnabled": True},
    )
    ctx.on_cleanup(lambda: cgp.delete_profiling_group(profilingGroupName=name))

    # Three distinct, real, currently-existing IAM principals: account root, the
    # caller's own ARN, and a freshly created role.
    p1 = f"arn:aws:iam::{account_id}:root"
    p2 = sts.get_caller_identity()["Arn"]
    p3_role_name = ctx.unique_name("sim2real-behav-role-")
    p3 = iam.create_role(RoleName=p3_role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"][
        "Arn"
    ]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=p3_role_name))

    rev1 = cgp.put_permission(
        profilingGroupName=name, actionGroup="agentPermissions", principals=[p1]
    )["revisionId"]
    rev2_resp = cgp.put_permission(
        profilingGroupName=name,
        actionGroup="agentPermissions",
        principals=[p1, p2],
        revisionId=rev1,
    )
    rev2 = rev2_resp["revisionId"]
    ctx.on_cleanup(
        lambda: cgp.remove_permission(
            profilingGroupName=name,
            actionGroup="agentPermissions",
            revisionId=cgp.get_policy(profilingGroupName=name)["revisionId"],
        )
    )

    # Break exactly one thing: reuse the stale rev1, not the current rev2.
    # (Wait out any principal-propagation lag for the freshly created role first,
    # by using a bounded retry that only swallows the "unrecognized principal"
    # ValidationException -- any other outcome, including the ConflictException
    # we actually expect once the stale revisionId is evaluated, is returned.)
    def _attempt_with_stale_revision():
        return _error(
            lambda: cgp.put_permission(
                profilingGroupName=name,
                actionGroup="agentPermissions",
                principals=[p3],
                revisionId=rev1,
            )
        )

    err = _retry_until_recognized_or_conflict(_attempt_with_stale_revision)
    assert err["Code"] == "ConflictException", err
    # AWS words this refusal two ways; both are built from values the check holds.
    expected = (
        "Trying to update an outdated revision, please retry!",
        f"Policy has been updated since the revision: {rev1}, new RevisionId: {rev2}",
    )
    assert err["Message"] in expected, (err["Message"], expected)

    # Effect absent: policy is still exactly rev2's content, p3 was never added.
    got = cgp.get_policy(profilingGroupName=name)
    assert got["revisionId"] == rev2
    assert p3 not in got["policy"]
    assert p2 in got["policy"]

    # Positive control: PutPermission with the correct current revisionId succeeds.
    rev3_resp = _retry_until_principal_recognized(
        lambda: cgp.put_permission(
            profilingGroupName=name,
            actionGroup="agentPermissions",
            principals=[p1, p2, p3],
            revisionId=rev2,
        )
    )
    assert rev3_resp["revisionId"] != rev2
    assert p3 in rev3_resp["policy"]

    # Terminal read: independent GetPolicy (not the mutating PutPermission's own
    # response) confirms the restore actually landed at the destination.
    final = cgp.get_policy(profilingGroupName=name)
    assert final["revisionId"] == rev3_resp["revisionId"], (
        f"expected independent get_policy revisionId {rev3_resp['revisionId']!r}, "
        f"got {final['revisionId']!r}"
    )
    assert p3 in final["policy"], f"expected {p3} in independently-read policy, got {final['policy']!r}"


def _retry_until_recognized_or_conflict(probe, timeout_s=30.0, interval_s=2.0):
    """probe() returns a botocore error dict, or raises if the call unexpectedly
    succeeded. Retry while it reports the principal-unrecognized ValidationException;
    stop as soon as it reports anything else (in particular the expected
    ConflictException)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last["Code"] != "ValidationException":
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
