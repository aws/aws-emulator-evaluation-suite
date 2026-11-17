"""tenant-suppression-half-pair-rejected-baseline-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-suppression-half-pair-rejected-baseline-unchanged"
GROUP = "tenants"
SERVICES = ["sesv2"]

_HALF_PAIR_REJECTED = (
    "BadRequestException",
    "SuppressedReasons cannot be specified without SuppressionScope.",
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _expect_error(fn, code, message) -> None:
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTenantSuppressionAttributes with SuppressedReasons but no SuppressionScope is refused
    and leaves an already-established suppression configuration unchanged; the full pair then
    updates it exactly, and a call naming only TenantName clears it to absent."""
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")

    sesv2.create_tenant(TenantName=tenant_name)
    ctx.on_cleanup(_ignore_not_found_cleanup(sesv2, tenant_name))

    # A non-null baseline makes the refusal's "unchanged" claim meaningful: a fresh tenant's
    # suppression attributes start out null, so testing against null alone would not show whether
    # the refused call left an established configuration alone.
    sesv2.put_tenant_suppression_attributes(
        TenantName=tenant_name, SuppressionScope="TENANT", SuppressedReasons=["COMPLAINT"],
    )
    baseline = sesv2.get_tenant(TenantName=tenant_name)["Tenant"]["SuppressionAttributes"]
    assert baseline == {"SuppressionScope": "TENANT", "SuppressedReasons": ["COMPLAINT"]}, (
        f"expected the established baseline, got {baseline!r}"
    )

    _expect_error(
        lambda: sesv2.put_tenant_suppression_attributes(
            TenantName=tenant_name, SuppressedReasons=["BOUNCE"],
        ),
        *_HALF_PAIR_REJECTED,
    )
    after_refusal = sesv2.get_tenant(TenantName=tenant_name)["Tenant"]["SuppressionAttributes"]
    assert after_refusal == baseline, (
        f"the refused call changed suppression attributes from {baseline!r} to {after_refusal!r}"
    )

    sesv2.put_tenant_suppression_attributes(
        TenantName=tenant_name, SuppressionScope="TENANT", SuppressedReasons=["BOUNCE", "COMPLAINT"],
    )
    updated = sesv2.get_tenant(TenantName=tenant_name)["Tenant"]["SuppressionAttributes"]
    assert updated["SuppressionScope"] == "TENANT", (
        f"expected SuppressionScope TENANT, got {updated['SuppressionScope']!r}"
    )
    assert sorted(updated["SuppressedReasons"]) == ["BOUNCE", "COMPLAINT"], (
        f"expected SuppressedReasons [BOUNCE, COMPLAINT], got {sorted(updated['SuppressedReasons'])}"
    )

    sesv2.put_tenant_suppression_attributes(TenantName=tenant_name)
    cleared = sesv2.get_tenant(TenantName=tenant_name)["Tenant"].get("SuppressionAttributes")
    assert cleared is None, f"expected suppression attributes cleared to None, got {cleared!r}"


def _ignore_not_found_cleanup(sesv2, tenant_name: str):
    return lambda: _ignore_not_found(lambda: sesv2.delete_tenant(TenantName=tenant_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
