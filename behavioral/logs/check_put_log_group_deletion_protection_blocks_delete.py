"""put-log-group-deletion-protection-blocks-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _safe_delete(svc, name):
    """Drop deletion protection, then delete; a group the check already removed is fine."""
    try:
        svc.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=False)
        svc.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise

CHECK = "put-log-group-deletion-protection-blocks-delete"
GROUP = 'log-group-lifecycle'
SERVICES = ['logs']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: DeleteLogGroup must fail while deletion protection is enabled."""
    svc = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-protect-")
    svc.create_log_group(logGroupName=name)
    ctx.on_cleanup(lambda _n=name: _safe_delete(svc, _n))

    def _described():
        groups = {
            g["logGroupName"]: g
            for g in svc.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
        }
        return groups.get(name)

    # Positive control: freshly created, protection is off.
    baseline = _described()
    assert baseline is not None, f"{name} not found after create"
    assert not baseline.get("deletionProtectionEnabled", False), baseline

    # Break exactly one thing.
    svc.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=True)
    enabled = _described()
    assert enabled is not None and enabled.get("deletionProtectionEnabled") is True, enabled

    # Real AWS rejects the delete with InvalidParameterException while the
    # deletion-protection flag is set (empirically observed, not from docs).
    code, message = _client_error(lambda: svc.delete_log_group(logGroupName=name))
    assert code == "InvalidParameterException", (
        f"expected delete to be blocked by deletion protection with "
        f"InvalidParameterException, got {code}"
    )
    assert message == (
        "LogGroup has delete protection enabled. Disable delete protection before attempting to "
        "delete the resource."
    ), f"unexpected message: {message!r}"

    # The forbidden effect did not happen: an independent read still finds it.
    still_there = _described()
    assert still_there is not None, f"{name} vanished despite the blocked delete"

    # Restore, then the identical delete call succeeds.
    svc.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=False)
    disabled = _described()
    assert disabled is not None and not disabled.get("deletionProtectionEnabled", False), disabled
    svc.delete_log_group(logGroupName=name)

    after = _described()
    assert after is None, f"{name} still present after delete"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
