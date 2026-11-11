"""domain-name-case-insensitive-across-availability-and-transferability."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "domain-name-case-insensitive-across-availability-and-transferability"
GROUP = "domain-name-normalization"
SERVICES = ["route53domains"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A mixed-case domain name reaches the same availability and transferability answer
    as its lowercase form, across two independent operations.
    """
    r53d = ctx.client("route53domains", region="us-east-1")
    label = ctx.unique_name("sim2real-behav-r53d-case-")
    lower = f"{label}.com"
    mixed = "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(lower))
    assert mixed != lower, "the mixed-case variant must actually differ from the lowercase one"

    lower_avail = r53d.check_domain_availability(DomainName=lower)["Availability"]
    mixed_avail = r53d.check_domain_availability(DomainName=mixed)["Availability"]
    assert lower_avail == mixed_avail, (
        f"CheckDomainAvailability disagreed by case: lowercase {lower!r} -> {lower_avail!r}, "
        f"mixed-case {mixed!r} -> {mixed_avail!r}"
    )

    lower_transfer = r53d.check_domain_transferability(DomainName="example.com")
    mixed_transfer = r53d.check_domain_transferability(DomainName="EXAMPLE.com")
    assert (
        lower_transfer["Transferability"]["Transferable"]
        == mixed_transfer["Transferability"]["Transferable"]
    ), (
        "CheckDomainTransferability disagreed by case: "
        f"{lower_transfer['Transferability']!r} vs {mixed_transfer['Transferability']!r}"
    )
    assert lower_transfer["Message"] == mixed_transfer["Message"], (
        f"CheckDomainTransferability message differs by case: {lower_transfer['Message']!r} "
        f"vs {mixed_transfer['Message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
