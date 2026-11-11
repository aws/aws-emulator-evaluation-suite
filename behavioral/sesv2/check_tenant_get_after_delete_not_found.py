"""tenant-get-after-delete-not-found."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-get-after-delete-not-found"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteTenant, GetTenant and a second DeleteTenant on the same tenant both fail with
    NotFoundException, and the freed name can be reused by a fresh CreateTenant.
    """
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-tenant-")

    sesv2.create_tenant(TenantName=name)
    # Register a defensive cleanup in case the delete below unexpectedly fails.
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, name))

    # Positive control: the tenant is reachable right after creation.
    got = sesv2.get_tenant(TenantName=name)["Tenant"]
    assert got["TenantName"] == name, f"expected TenantName {name!r}, got {got['TenantName']!r}"

    sesv2.delete_tenant(TenantName=name)

    expected_msg = f"The requested tenant <{name}> does not exist."
    code, msg = _error(lambda: sesv2.get_tenant(TenantName=name))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading a deleted tenant, got {code!r}"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # A mutation on the same dead id must also fail, not silently no-op or resurrect anything.
    delete_code, delete_msg = _error(lambda: sesv2.delete_tenant(TenantName=name))
    assert delete_code == "NotFoundException", (
        f"expected NotFoundException deleting an already-deleted tenant, got {delete_code!r}"
    )
    assert delete_msg == expected_msg, f"expected message {expected_msg!r}, got {delete_msg!r}"

    # The freed name is reusable: a fresh CreateTenant with the identical name must succeed and
    # be independently readable, proving the delete was a genuine terminal removal rather than a
    # reservation that would otherwise surface as a name conflict.
    sesv2.create_tenant(TenantName=name)
    recreated = sesv2.get_tenant(TenantName=name)["Tenant"]
    assert recreated["TenantName"] == name, (
        f"expected the reused name to resolve to a fresh tenant, got {recreated['TenantName']!r}"
    )


def _error(fn: Callable[[], object]) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message) it is refused with. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete_tenant(sesv2, name: str) -> None:
    try:
        sesv2.delete_tenant(TenantName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
