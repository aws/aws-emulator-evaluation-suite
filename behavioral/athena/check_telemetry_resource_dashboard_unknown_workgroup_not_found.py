"""telemetry-resource-dashboard-unknown-workgroup-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "telemetry-resource-dashboard-unknown-workgroup-not-found"
GROUP = "telemetry"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceDashboard on a session ARN that does not resolve (missing session under a real
    workgroup, or a workgroup never created) raises InvalidRequestException "ResourceARN is not
    found": Athena treats an unresolvable session reference as a request validation failure."""
    athena = ctx.client("athena")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Control first: a real workgroup exists, but no session was ever started under
    # it. GetResourceDashboard against a session ARN scoped to this genuinely existing
    # workgroup, with a session id that was never created, still raises
    # InvalidRequestException -- proving the rejection is about the missing session
    # resource itself, not about broken ARN/account/workgroup plumbing (an ARN this
    # malformed, or an account/region mismatch, would fail differently or earlier).
    wg_name = ctx.unique_name("sim2real-athena-dash-ctrl-wg-")
    athena.create_work_group(Name=wg_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe(lambda: athena.delete_work_group(WorkGroup=wg_name)))
    wg = athena.get_work_group(WorkGroup=wg_name)["WorkGroup"]
    assert wg["Name"] == wg_name, f"expected the just-created workgroup {wg_name!r}, got {wg['Name']!r}"

    # The session id is well-formed ("s-" plus lowercase alphanumerics, the shape the
    # ResourceARN pattern requires) so the refusal is the lookup, not input validation.
    not_found = ("InvalidRequestException", "ResourceARN is not found")
    bogus_session_arn = (
        f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{wg_name}"
        f"/session/{ctx.unique_name('s-')}"
    )
    err = _error(lambda: athena.get_resource_dashboard(ResourceARN=bogus_session_arn))
    assert err == not_found, (
        f"expected {not_found} for a nonexistent session under a real, "
        f"resolvable workgroup, got {err!r}"
    )

    # Also confirm a workgroup that never existed at all produces a clear rejection
    # rather than an empty/default dashboard payload (broader boundary: no ambient
    # resource, no ambient session). Real Athena rejects this the same way it rejected
    # the resolvable-workgroup/missing-session ARN above.
    missing_wg_name = ctx.unique_name("sim2real-athena-missing-wg-")
    fully_bogus_arn = (
        f"arn:aws:athena:{ctx.region}:{account_id}:workgroup/{missing_wg_name}"
        f"/session/{ctx.unique_name('s-')}"
    )
    err2 = _error(lambda: athena.get_resource_dashboard(ResourceARN=fully_bogus_arn))
    assert err2 == not_found, (
        f"expected {not_found} for a workgroup that was never created, got {err2!r}"
    )


def _safe(fn) -> None:
    """Run a teardown call; return only on Athena's not-found refusal, raise anything else."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        if error.get("Code") != "InvalidRequestException" or "not found" not in error.get("Message", "").lower():
            raise


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
