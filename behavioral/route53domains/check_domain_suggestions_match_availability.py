"""domain-suggestions-match-availability."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "domain-suggestions-match-availability"
GROUP = "domain-research"
SERVICES = ["route53domains"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDomainSuggestions with OnlyAvailable=True returns only names CheckDomainAvailability
    independently reports AVAILABLE for.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_GetDomainSuggestions.html
    """
    r53 = ctx.client("route53domains", region="us-east-1")
    base = ctx.unique_name("sim2real-behav-r53d-")
    base_domain = f"{base}.com"

    suggested = r53.get_domain_suggestions(
        DomainName=base_domain, SuggestionCount=10, OnlyAvailable=True
    )["SuggestionsList"]
    assert len(suggested) > 0, f"expected at least one suggestion for {base_domain!r}, got none"

    for entry in suggested:
        name = entry["DomainName"]
        assert entry["Availability"] == "AVAILABLE", (
            f"suggestion {name!r} was returned with Availability {entry['Availability']!r}, "
            "not AVAILABLE, even though the request asked for OnlyAvailable=True"
        )
        independent = r53.check_domain_availability(DomainName=name)["Availability"]
        assert independent == "AVAILABLE", (
            f"GetDomainSuggestions offered {name!r} as available, but an independent "
            f"CheckDomainAvailability call reports {independent!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
