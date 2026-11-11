"""get-distribution-tenant-by-domain-not-found-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "get-distribution-tenant-by-domain-not-found-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDistributionTenantByDomain for a domain that was never associated
    with any distribution tenant MUST fail with EntityNotFound."""
    cf = ctx.client("cloudfront")
    bogus_domain = f"{ctx.unique_name('sim2real-behav-nope-')}.sim2real-behav-test.example.com"
    code, message = _error(lambda: cf.get_distribution_tenant_by_domain(Domain=bogus_domain))
    assert code == "EntityNotFound", f"expected EntityNotFound for an unassociated domain, got {code}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
