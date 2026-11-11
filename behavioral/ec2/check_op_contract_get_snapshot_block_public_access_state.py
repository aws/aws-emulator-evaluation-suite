"""op-contract-get-snapshot-block-public-access-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-snapshot-block-public-access-state"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-snapshot-block-public-access")
def run(ctx) -> None:
    """GetSnapshotBlockPublicAccessState returns a State and ManagedBy from the documented enums and, when
    the setting is account-managed, the exact state the check just set; DryRun fails with
    DryRunOperation and the standard message."""
    import time

    ec2 = ctx.client("ec2")

    resp = ec2.get_snapshot_block_public_access_state()
    assert resp["State"] in ("block-all-sharing", "block-new-sharing", "unblocked"), resp
    assert resp["ManagedBy"] in ("account", "declarative-policy"), resp
    original_state = resp["State"]

    # Derive the expected value from the account's own reaction to a call this check
    # makes, instead of accepting any documented enum member: a target that always
    # answers a fixed state (or ignores EnableSnapshotBlockPublicAccess entirely) must
    # fail this. Skip the mutation only when the account itself reports the setting as
    # declarative-policy-managed, where Enable/Disable are documented to be rejected.
    if resp["ManagedBy"] == "account":

        def _restore():
            if original_state == "unblocked":
                ec2.disable_snapshot_block_public_access()
            else:
                ec2.enable_snapshot_block_public_access(State=original_state)

        ctx.on_cleanup(_restore)

        target_state = "block-all-sharing" if original_state != "block-all-sharing" else "block-new-sharing"
        ec2.enable_snapshot_block_public_access(State=target_state)

        deadline = time.monotonic() + 180.0
        seen = None
        while time.monotonic() < deadline:
            seen = ec2.get_snapshot_block_public_access_state()["State"]
            if seen == target_state:
                break
            time.sleep(5.0)
        assert seen == target_state, (
            f"GetSnapshotBlockPublicAccessState never reflected {target_state!r} within "
            f"180s of EnableSnapshotBlockPublicAccess; last saw {seen!r}"
        )

    # error boundary: this account genuinely has permission, so DryRun must yield the
    # documented DryRunOperation error, distinct from UnauthorizedOperation, and must
    # not actually perform the read.
    code, message = _client_error(lambda: ec2.get_snapshot_block_public_access_state(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
