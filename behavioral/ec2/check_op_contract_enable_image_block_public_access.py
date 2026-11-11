"""op-contract-enableImageBlockPublicAccess."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enableImageBlockPublicAccess"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-image-block-public-access")
def run(ctx) -> None:
    """EnableImageBlockPublicAccess: account-level setting contract + DryRun error boundary."""
    ec2 = ctx.client("ec2")

    original_state = ec2.get_image_block_public_access_state()["ImageBlockPublicAccessState"]

    def _restore():
        if original_state == "block-new-sharing":
            ec2.enable_image_block_public_access(ImageBlockPublicAccessState="block-new-sharing")
        else:
            ec2.disable_image_block_public_access()

    ctx.on_cleanup(_restore)

    resp = ec2.enable_image_block_public_access(ImageBlockPublicAccessState="block-new-sharing")
    assert resp["ImageBlockPublicAccessState"] == "block-new-sharing", (
        f"expected block-new-sharing, got {resp['ImageBlockPublicAccessState']!r}"
    )

    converged = _poll_until(
        lambda: ec2.get_image_block_public_access_state()["ImageBlockPublicAccessState"],
        lambda s: s == "block-new-sharing",
        timeout_s=30,
        interval_s=5,
    )
    assert converged == "block-new-sharing", f"expected block-new-sharing, got {converged!r}"

    # Error boundary: DryRun must short-circuit to DryRunOperation, not actually apply anything.
    code, message = _client_error(lambda: ec2.enable_image_block_public_access(
        ImageBlockPublicAccessState="block-new-sharing", DryRun=True
    ))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_message = "Request would have succeeded, but DryRun flag is set."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"did not converge within {timeout_s}s, last value {value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
