"""image-block-public-access-state-reflects-setting."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "image-block-public-access-state-reflects-setting"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ec2-image-block-public-access")
def run(ctx) -> None:
    """GetImageBlockPublicAccessState settles to the blocked/unblocked state exactly as last configured."""
    ec2 = ctx.client("ec2")

    original = ec2.get_image_block_public_access_state()
    if original.get("ManagedBy") == "declarative-policy":
        raise AssertionError(
            "image block public access is managed by a declarative policy in this account "
            "and cannot be modified directly by Enable/DisableImageBlockPublicAccess"
        )
    original_state = original["ImageBlockPublicAccessState"]

    def _restore():
        if original_state == "unblocked":
            ec2.disable_image_block_public_access()
        else:
            ec2.enable_image_block_public_access(ImageBlockPublicAccessState="block-new-sharing")

    ctx.on_cleanup(_restore)

    ec2.enable_image_block_public_access(ImageBlockPublicAccessState="block-new-sharing")
    blocked = _settled_state(ctx, ec2, "block-new-sharing")
    assert blocked == "block-new-sharing", f"expected block-new-sharing, got {blocked!r}"

    ec2.disable_image_block_public_access()
    unblocked = _settled_state(ctx, ec2, "unblocked")
    assert unblocked == "unblocked", f"expected unblocked, got {unblocked!r}"


def _settled_state(ctx, ec2, expected, cap_s=120.0, interval_s=3.0):
    """The account's image BPA state once it reads `expected`, or the last state read when the
    deadline (cap_s, bounded by the run budget) passes; the setting takes a moment to propagate."""
    left = ctx.time_left()
    deadline = time.monotonic() + (cap_s if left is None else max(1.0, min(cap_s, left - 10.0)))
    while True:
        state = ec2.get_image_block_public_access_state()["ImageBlockPublicAccessState"]
        if state == expected or time.monotonic() >= deadline:
            return state
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
