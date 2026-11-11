"""op-contract-get-invalidation-for-distribution-tenant-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-get-invalidation-for-distribution-tenant-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInvalidationForDistributionTenant answers an unknown tenant Id with EntityNotFound and the exact message
    "DistributionTenantId format is invalid"; ListDistributionTenants answers with a list without that Id, so the
    refusal is not a blanket denial of the tenant API."""
    cf = ctx.client("cloudfront")

    # Positive control: a plain list needs no certificate, domain or tenant, so a target that
    # denies every distribution-tenant call fails here rather than at the not-found answer below.
    listed = cf.list_distribution_tenants()
    assert "DistributionTenantList" in listed, (
        f"expected ListDistributionTenants to answer with a DistributionTenantList, got {listed!r}"
    )

    bogus_tenant_id = "dt-sim2real-bogus-0000000000"
    bogus_invalidation_id = "IBOGUSTENANTINVALIDATION00"

    code, message = _error(
        lambda: cf.get_invalidation_for_distribution_tenant(
            DistributionTenantId=bogus_tenant_id,
            Id=bogus_invalidation_id,
        )
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    assert message == "DistributionTenantId format is invalid", (
        f"expected AWS's exact message, got {message!r}"
    )

    # The unknown tenant Id is absent from the tenant listing as well.
    ids = [t.get("Id") for t in listed["DistributionTenantList"]]
    assert bogus_tenant_id not in ids, (
        f"expected {bogus_tenant_id!r} to be absent from ListDistributionTenants, found it in {ids!r}"
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
