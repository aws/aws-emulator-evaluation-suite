"""invalidation-for-distribution-tenant-quantity-validated-before-tenant-lookup."""
from __future__ import annotations

import random
import string

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalidation-for-distribution-tenant-quantity-validated-before-tenant-lookup"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

#: A path item in cache-tag form, and an ordinary path item, mixed in one batch.
_MIXED_PATHS = ["#brand:acme", "/index.html"]

_QUANTITY_MISMATCH = (
    "InconsistentQuantities",
    f"The specified quantity of Paths (1) does not match the actual quantity supplied "
    f"({len(_MIXED_PATHS)}).",
)
_TENANT_NOT_FOUND = ("EntityNotFound", "The specified distribution tenant doesn't exist.")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvalidationForDistributionTenant checks Paths.Quantity against the Items it
    actually carries before it ever looks up the distribution tenant.
    """
    cf = ctx.client("cloudfront")
    # A tenant id this account never created, but shaped like a real one (CloudFront rejects a
    # malformed id with InvalidArgument("Id format is invalid") before any other validation,
    # which would mask the quantity check this probes).
    bogus_tenant_id = _well_formed_tenant_id()

    expect_error(
        lambda: cf.create_invalidation_for_distribution_tenant(
            Id=bogus_tenant_id,
            InvalidationBatch={
                "CallerReference": ctx.unique_name("cfq-mismatch-"),
                "Paths": {"Quantity": 1, "Items": _MIXED_PATHS},
            },
        ),
        *_QUANTITY_MISMATCH,
    )

    # Positive control, same tenant id: a batch whose declared Quantity matches its Items count
    # clears shape validation and reaches the tenant lookup, which answers distinctly.
    expect_error(
        lambda: cf.create_invalidation_for_distribution_tenant(
            Id=bogus_tenant_id,
            InvalidationBatch={
                "CallerReference": ctx.unique_name("cfq-consistent-"),
                "Paths": {"Quantity": len(_MIXED_PATHS), "Items": _MIXED_PATHS},
            },
        ),
        *_TENANT_NOT_FOUND,
    )


def _well_formed_tenant_id() -> str:
    """A syntactically valid, never-issued distribution-tenant id: "dt_" plus 27 base62 chars,
    matching the shape CloudFront's real ids take (e.g. "dt_3JO1OQa51Jb3BZh7XQh6pbvF3Wa")."""
    alphabet = string.ascii_letters + string.digits
    return "dt_" + "".join(random.choices(alphabet, k=27))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
