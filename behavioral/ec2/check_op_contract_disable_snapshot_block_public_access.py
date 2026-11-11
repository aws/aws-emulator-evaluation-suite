"""op-contract-disable-snapshot-block-public-access."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-disable-snapshot-block-public-access"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-snapshot-block-public-access")
def run(ctx) -> None:
    """DisableSnapshotBlockPublicAccess flips the account setting back to 'unblocked',
    and its DryRun contract reports DryRunOperation without changing state."""
    ec2 = ctx.client("ec2")

    original_state = ec2.get_snapshot_block_public_access_state()["State"]

    def _restore():
        if original_state == "unblocked":
            ec2.disable_snapshot_block_public_access()
        else:
            ec2.enable_snapshot_block_public_access(State=original_state)

    ctx.on_cleanup(_restore)

    # Put the account into a known non-default state first so the disable call
    # has an observable effect.
    ec2.enable_snapshot_block_public_access(State="block-new-sharing")
    enabled_state = ec2.get_snapshot_block_public_access_state()["State"]
    assert enabled_state == "block-new-sharing", f"expected block-new-sharing, got {enabled_state}"

    resp = ec2.disable_snapshot_block_public_access()
    assert resp["State"] == "unblocked", f"expected unblocked, got {resp['State']}"

    after = ec2.get_snapshot_block_public_access_state()["State"]
    assert after == "unblocked", f"expected unblocked, got {after}"

    # Error boundary: DryRun must report DryRunOperation and must not change state.
    code, message = _client_error(lambda: ec2.disable_snapshot_block_public_access(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    still_after = ec2.get_snapshot_block_public_access_state()["State"]
    assert still_after == "unblocked", f"expected unblocked, got {still_after}"


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
