"""op-contract-disable-image-block-public-access."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-image-block-public-access"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-image-block-public-access")
def run(ctx) -> None:
    """DisableImageBlockPublicAccess returns unblocked and GetImageBlockPublicAccessState converges to
    unblocked, with the prior setting restored afterwards; DryRun answers DryRunOperation with its
    exact message."""
    ec2 = ctx.client("ec2")

    original = ec2.get_image_block_public_access_state()["ImageBlockPublicAccessState"]

    def _restore():
        if original != "unblocked":
            ec2.enable_image_block_public_access(ImageBlockPublicAccessState="block-new-sharing")

    ctx.on_cleanup(_restore)

    resp = ec2.disable_image_block_public_access()
    assert resp["ImageBlockPublicAccessState"] == "unblocked"

    state = _poll_until(
        lambda: ec2.get_image_block_public_access_state()["ImageBlockPublicAccessState"],
        lambda s: s == "unblocked",
        timeout_s=30.0,
    )
    assert state == "unblocked", f"state did not converge to unblocked: {state}"

    code, message = _error(lambda: ec2.disable_image_block_public_access(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
