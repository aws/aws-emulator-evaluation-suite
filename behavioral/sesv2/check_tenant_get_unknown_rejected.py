"""tenant-get-unknown-rejected."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-get-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTenant for a tenant name that was never created raises NotFoundException, while a
    real tenant remains reachable through the same operation."""
    sesv2 = ctx.client("sesv2")
    unknown_name = ctx.unique_name("sim2real-tenant-unknown-")
    control_name = ctx.unique_name("sim2real-tenant-ctl-")

    expected_msg = f"The requested tenant <{unknown_name}> does not exist."
    code, msg = _error(lambda: sesv2.get_tenant(TenantName=unknown_name))
    assert code == "NotFoundException", f"expected NotFoundException for GetTenant({unknown_name!r}), got {code!r}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the failed lookup did not fabricate/create a tenant.
    code_again, msg_again = _error(lambda: sesv2.get_tenant(TenantName=unknown_name))
    assert code_again == "NotFoundException", (
        f"expected the repeated GetTenant({unknown_name!r}) to still raise NotFoundException, "
        f"got {code_again!r}"
    )
    assert msg_again == expected_msg, f"expected message {expected_msg!r}, got {msg_again!r}"

    # Positive control: GetTenant on a real tenant succeeds.
    sesv2.create_tenant(TenantName=control_name)
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, control_name))
    control = sesv2.get_tenant(TenantName=control_name)["Tenant"]
    assert control["TenantName"] == control_name, (
        f"expected GetTenant to return the control tenant {control_name!r}, got {control!r}"
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
