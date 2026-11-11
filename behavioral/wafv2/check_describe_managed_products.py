"""describe-managed-products."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-managed-products"
GROUP = 'managed-rule-groups'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    retryable = codes or _TRANSIENT_CODES
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in retryable:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAllManagedProducts and DescribeManagedProductsByVendor agree for vendor AWS."""
    w = ctx.client("wafv2")
    all_products = _retry_transient(
        lambda: w.describe_all_managed_products(Scope=SCOPE)
    )["ManagedProducts"]
    assert len(all_products) > 0, "DescribeAllManagedProducts returned an empty catalog"

    aws_products = _retry_transient(
        lambda: w.describe_managed_products_by_vendor(VendorName="AWS", Scope=SCOPE)
    )["ManagedProducts"]
    assert len(aws_products) > 0, (
        "DescribeManagedProductsByVendor(VendorName=AWS) returned no products"
    )
    assert all(p["VendorName"] == "AWS" for p in aws_products), aws_products[:3]

    all_aws = {p["ManagedRuleSetName"] for p in all_products if p["VendorName"] == "AWS"}
    by_vendor = {p["ManagedRuleSetName"] for p in aws_products}
    assert by_vendor == all_aws, (by_vendor ^ all_aws)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
