"""op-contract-getSdkTypes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-getSdkTypes"
GROUP = "error-semantics"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSdkTypes lists the built-in SDK types with a friendlyName each, and an unrecognized
    position token is ignored rather than rejected: the catalog is small and not truly paginated,
    so the same full listing comes back."""
    apigw = ctx.client("apigateway")

    listing = apigw.get_sdk_types()
    items = listing["items"]
    # The exact set of built-in SDK generators is account/region dependent
    # (e.g. "javascript" is not always present), so assert against the
    # actual returned listing rather than hardcoded ids.
    assert items, "expected at least one built-in SDK type"
    ids = {item["id"] for item in items}
    sample_id = next(iter(ids))
    sample = next(item for item in items if item["id"] == sample_id)
    assert isinstance(sample["friendlyName"], str) and len(sample["friendlyName"]) > 0, (
        f"expected a non-empty string friendlyName for sdk type {sample_id!r}, got {sample.get('friendlyName')!r}"
    )

    # Real AWS does not validate/reject a bogus position token for this
    # endpoint (the catalog is fixed-size and not actually paginated); it
    # simply returns the same full catalog again.
    reissued = apigw.get_sdk_types(position="not-a-valid-pagination-token")
    reissued_ids = {item["id"] for item in reissued["items"]}
    assert reissued_ids == ids, (
        f"expected the same catalog ids when reissued with a bogus position token, "
        f"got {reissued_ids!r} vs original {ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
