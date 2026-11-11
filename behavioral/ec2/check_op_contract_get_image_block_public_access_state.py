"""op-contract-get-image-block-public-access-state."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-image-block-public-access-state"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetImageBlockPublicAccessState returns the documented account-level enum,
    and DryRun short-circuits with the standard permission-check error."""
    ec2 = ctx.client("ec2")

    resp = ec2.get_image_block_public_access_state()
    state = resp["ImageBlockPublicAccessState"]
    assert state in ("block-new-sharing", "unblocked"), state
    # ManagedBy's full modelled enum is exactly {"account", "declarative-policy"} (verified
    # against the EC2 Smithy model), so accepting both is a tautology against any conformant
    # target. In a standalone account with no AWS Organizations declarative policy in effect,
    # the only value a correct target can report here is "account".
    managed_by = resp["ManagedBy"]
    assert managed_by == "account", f"expected account-managed (no declarative policy in this sandbox), got {managed_by!r}"

    code, message = _error(lambda: ec2.get_image_block_public_access_state(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, message


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
