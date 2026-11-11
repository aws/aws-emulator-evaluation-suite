"""op-contract-get-invalidation-for-distribution-tenant."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-invalidation-for-distribution-tenant"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInvalidationForDistributionTenant answers an unknown distribution tenant Id with EntityNotFound and
    the exact message "DistributionTenantId format is invalid"."""
    cf = ctx.client("cloudfront")

    # error boundary: unknown distribution tenant Id
    err, message = _error(
        lambda: cf.get_invalidation_for_distribution_tenant(
            DistributionTenantId="dt_sim2real0000000000",
            Id="IBOGUS0000000000",
        )
    )
    assert err == "EntityNotFound", f"expected EntityNotFound for an unknown distribution tenant, got {err}"
    assert message == "DistributionTenantId format is invalid", (
        f"expected AWS's exact message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises: accepting what AWS refuses
    is a finding in itself, not a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
