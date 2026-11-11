"""op-contract-get-capacity-manager-attributes."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-capacity-manager-attributes"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-capacity-manager")
def run(ctx) -> None:
    """GetCapacityManagerAttributes fails with CapacityManager.Disabled and its exact message while
    Capacity Manager is off; once enabled it reports status "enabled" with typed export, ingestion
    and OrganizationsAccess fields; DryRun answers DryRunOperation with the standard message."""
    ec2 = ctx.client("ec2")
    from botocore.exceptions import ClientError

    # --- error boundary: DryRun permission check is evaluated ahead of the enablement
    # state, so it reports DryRunOperation regardless (matches DisableCapacityManager's
    # documented ordering; the account is not yet known to be enabled at this point) ---
    code, message = _error(lambda: ec2.get_capacity_manager_attributes(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, message

    def _read():
        return ec2.get_capacity_manager_attributes()

    # --- baseline: a never-enabled account rejects the read with the documented error ---
    try:
        attrs = _read()
        already_enabled = True
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "CapacityManager.Disabled", exc.response["Error"]
        assert exc.response["Error"].get("Message") == "Capacity Manager isn't enabled for this account.", exc.response["Error"]
        already_enabled = False

    if not already_enabled:
        # POSITIVE: drive the account into the enabled state ourselves, so the success
        # shape below is exercised for real on this run rather than accepted only when
        # some earlier run happened to leave it on -- a target that fakes both branches
        # by always answering CapacityManager.Disabled must fail here.
        ec2.enable_capacity_manager(OrganizationsAccess=False)
        ctx.on_cleanup(lambda: _safe(lambda: ec2.disable_capacity_manager()))
        attrs = _poll_until(
            _read, lambda a: a["CapacityManagerStatus"] == "enabled", timeout_s=120,
        )
        assert attrs["OrganizationsAccess"] is False, attrs
    else:
        assert isinstance(attrs.get("OrganizationsAccess"), bool), attrs.get("OrganizationsAccess")

    assert attrs["CapacityManagerStatus"] == "enabled", attrs
    assert isinstance(attrs.get("DataExportCount"), int), attrs.get("DataExportCount")
    assert attrs.get("IngestionStatus") in (
        "initial-ingestion-in-progress", "ingestion-complete", "ingestion-failed",
    ), attrs.get("IngestionStatus")


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


def _safe(fn: Callable[[], Any]) -> None:
    fn()


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float = 3.0):
    import time
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
