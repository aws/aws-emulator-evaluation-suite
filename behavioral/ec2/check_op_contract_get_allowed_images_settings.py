"""op-contract-get-allowed-images-settings."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-allowed-images-settings"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetAllowedImagesSettings returns the account-level Allowed AMIs state/manager,
    and honors the DryRun permission-check contract."""
    ec2 = ctx.client("ec2")

    # --- success path: well-formed account-level settings snapshot ---
    resp = ec2.get_allowed_images_settings()
    assert resp["State"] in ("disabled", "audit-mode", "enabled"), resp
    # ImageCriteria is only populated once Allowed AMIs has actually been configured
    # (enabled/audit-mode); a fresh account with State == "disabled" omits it entirely.
    if resp["State"] != "disabled":
        assert "ImageCriteria" in resp, resp
    if "ManagedBy" in resp:
        assert resp["ManagedBy"] in ("account", "declarative-policy"), resp["ManagedBy"]

    # --- error boundary: DryRun permission-check contract ---
    code, message = _error(lambda: ec2.get_allowed_images_settings(DryRun=True))
    assert code == "DryRunOperation", code
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
