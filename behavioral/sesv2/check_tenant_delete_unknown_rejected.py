"""tenant-delete-unknown-rejected."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-delete-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTenant for an unknown tenant name raises NotFoundException, leaves an unrelated
    real tenant untouched, and a subsequent delete of the real tenant still succeeds."""
    sesv2 = ctx.client("sesv2")
    real_name = ctx.unique_name("sim2real-tenant-real-")
    unknown_name = ctx.unique_name("sim2real-tenant-unknown-")

    sesv2.create_tenant(TenantName=real_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, real_name))

    code, msg = _error(lambda: sesv2.delete_tenant(TenantName=unknown_name))
    assert code == "NotFoundException", f"expected NotFoundException deleting an unknown tenant, got {code!r}"
    expected_msg = f"The requested tenant <{unknown_name}> does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the erroneous delete on the unknown name did not touch the real tenant.
    still_there = sesv2.get_tenant(TenantName=real_name)["Tenant"]
    assert still_there["TenantName"] == real_name, (
        f"expected the real tenant {real_name!r} to be untouched, got {still_there['TenantName']!r}"
    )

    # Positive control: deleting the real tenant succeeds and it is then gone.
    sesv2.delete_tenant(TenantName=real_name)
    code_after, msg_after = _error(lambda: sesv2.get_tenant(TenantName=real_name))
    assert code_after == "NotFoundException", (
        f"expected NotFoundException getting the now-deleted real tenant, got {code_after!r}"
    )
    expected_after = f"The requested tenant <{real_name}> does not exist."
    assert msg_after == expected_after, f"expected message {expected_after!r}, got {msg_after!r}"


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
