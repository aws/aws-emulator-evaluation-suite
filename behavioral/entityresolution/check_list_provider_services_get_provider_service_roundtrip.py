"""list-provider-services-get-provider-service-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-provider-services-get-provider-service-roundtrip"
GROUP = "control-plane"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListProviderServices returns AWS's built-in provider catalog, and GetProviderService for
    any listed summary returns matching identity fields (this is read-only reference data, not
    a caller-created resource, so there is nothing to clean up)."""
    er = ctx.client("entityresolution")
    summaries = er.list_provider_services().get("providerServiceSummaries", [])
    if not summaries:
        raise AssertionError("ListProviderServices returned no provider services in this account/region")

    first = summaries[0]
    got = er.get_provider_service(
        providerName=first["providerName"], providerServiceName=first["providerServiceArn"]
    )
    assert got["providerName"] == first["providerName"], (
        f"GetProviderService providerName mismatch: expected {first['providerName']!r}, "
        f"got {got['providerName']!r}"
    )
    assert got["providerServiceName"] == first["providerServiceName"], (
        f"GetProviderService providerServiceName mismatch: expected {first['providerServiceName']!r}, "
        f"got {got['providerServiceName']!r}"
    )
    assert got["providerServiceArn"] == first["providerServiceArn"], (
        f"GetProviderService providerServiceArn mismatch: expected {first['providerServiceArn']!r}, "
        f"got {got['providerServiceArn']!r}"
    )
    assert got["providerServiceType"] == first["providerServiceType"], (
        f"GetProviderService providerServiceType mismatch: expected {first['providerServiceType']!r}, "
        f"got {got['providerServiceType']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
