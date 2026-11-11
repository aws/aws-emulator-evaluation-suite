"""create-log-group-duplicate-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _matches(svc, name):
    resp = svc.describe_log_groups(logGroupNamePrefix=name)
    return [g for g in resp.get("logGroups", []) if g["logGroupName"] == name]

CHECK = "create-log-group-duplicate-fails"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: creating a log group that already exists must fail,
    the rejected duplicate must leave the original untouched, and the name
    must be reusable once the original is deleted."""
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-dup-")
    svc.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=name: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=name: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    code, msg = _error(lambda: svc.create_log_group(logGroupName=name))
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r} {msg!r}"
    assert msg == "The specified log group already exists", f"unexpected message: {msg!r}"

    matches = _matches(svc, name)
    assert len(matches) == 1, (
        f"expected exactly one log group named {name} after the rejected duplicate create, "
        f"found {len(matches)}"
    )

    svc.delete_log_group(logGroupName=name)
    assert _matches(svc, name) == [], f"{name} still visible in DescribeLogGroups after delete"

    svc.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    matches_after = _matches(svc, name)
    assert len(matches_after) == 1, (
        f"expected {name} to be creatable again once the original was deleted, "
        f"found {len(matches_after)} matches"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
