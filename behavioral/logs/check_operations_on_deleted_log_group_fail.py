"""operations-on-deleted-log-group-fail."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its (error code, error message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected an error but the call succeeded: {result!r}")

CHECK = "operations-on-deleted-log-group-fail"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: operations against a deleted log group must fail, not silently succeed."""
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-gone-")
    svc.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=name: _ignore_not_found(lambda: svc.delete_log_group(logGroupName=_n)))

    # positive control: the same call succeeds against the live group, so the later
    # failure is attributable to the deletion and not to a target that rejects every
    # CreateLogStream call regardless of state.
    svc.create_log_stream(logGroupName=name, logStreamName="s0")

    svc.delete_log_group(logGroupName=name)

    resp = svc.describe_log_groups(logGroupNamePrefix=name)
    assert not any(g["logGroupName"] == name for g in resp.get("logGroups", [])), (
        f"deleted log group {name} still listed by DescribeLogGroups"
    )

    code, msg = _error(lambda: svc.create_log_stream(logGroupName=name, logStreamName="s1"))
    assert code == "ResourceNotFoundException", f"got {code!r}"
    assert msg == "The specified log group does not exist.", f"got {msg!r}"


def _ignore_not_found(fn):
    """Teardown wrapper: the check deletes this resource itself, so a teardown that finds it
    already gone is the expected outcome, not a leak."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
