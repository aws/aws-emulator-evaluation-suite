"""tenant-create-duplicate-name-rejected."""
from __future__ import annotations

import time
from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-create-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTenant on a taken name raises AlreadyExistsException and leaves the original tenant intact, a
    distinct name still succeeds, and after the original is deleted the same name creates a tenant with a new
    id.
    """
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-tenant-")
    other_name = ctx.unique_name("sim2real-tenant-ctl-")

    created = sesv2.create_tenant(TenantName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, name))
    original_tenant_id = created["TenantId"]

    code, msg = _error(lambda: sesv2.create_tenant(TenantName=name))
    assert code == "AlreadyExistsException", (
        f"expected AlreadyExistsException for a duplicate tenant name, got {code!r}"
    )
    expected_msg = f"Tenant with name {name} already exists in account {ctx.account}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the duplicate attempt did not mutate/replace the original tenant.
    still_there = sesv2.get_tenant(TenantName=name)["Tenant"]
    assert still_there["TenantId"] == original_tenant_id, (
        f"expected original tenant id {original_tenant_id!r} unchanged, "
        f"got {still_there['TenantId']!r}"
    )
    assert still_there["TenantName"] == name, (
        f"expected tenant name {name!r}, got {still_there['TenantName']!r}"
    )

    # Positive control: creating a distinct tenant still works fine.
    sesv2.create_tenant(TenantName=other_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, other_name))
    control = sesv2.get_tenant(TenantName=other_name)["Tenant"]
    assert control["TenantName"] == other_name, (
        f"expected control tenant name {other_name!r}, got {control['TenantName']!r}"
    )

    # Restore: undo the block (delete the original) and demand the identical call now
    # succeeds — proving AlreadyExistsException tracks the live name, not a permanent hold.
    sesv2.delete_tenant(TenantName=name)
    _wait_until_not_found(lambda: sesv2.get_tenant(TenantName=name))

    recreated = sesv2.create_tenant(TenantName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    assert recreated["TenantId"] != original_tenant_id, (
        f"recreated tenant reused the original tenant id {original_tenant_id!r} "
        "instead of minting a new one"
    )
    reread = sesv2.get_tenant(TenantName=name)["Tenant"]
    assert reread["TenantId"] == recreated["TenantId"], (
        f"expected recreated tenant id {recreated['TenantId']!r}, got {reread['TenantId']!r}"
    )


def _error(fn: Callable[[], object]) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message) it is refused with. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_until_not_found(fn: Callable[[], object], *, timeout_s: float = 30.0,
                           interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(
        f"expected NotFoundException within {timeout_s}s of delete, last saw {last_code!r}"
    )


def _safe_delete_tenant(sesv2, name: str) -> None:
    try:
        sesv2.delete_tenant(TenantName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
