"""transferability-agrees-with-availability-for-unregistered-domain."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "transferability-agrees-with-availability-for-unregistered-domain"
GROUP = "domain-research"
SERVICES = ["route53domains"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A domain CheckDomainAvailability reports AVAILABLE is one CheckDomainTransferability
    independently reports UNTRANSFERABLE for, naming the same reason: it isn't registered.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_CheckDomainTransferability.html
    """
    r53 = ctx.client("route53domains", region="us-east-1")
    domain = f"{ctx.unique_name('sim2real-behav-r53d-')}.com"

    availability = r53.check_domain_availability(DomainName=domain)["Availability"]
    assert availability == "AVAILABLE", (
        f"expected the freshly generated domain {domain!r} to be AVAILABLE, got {availability!r}"
    )

    transferability = r53.check_domain_transferability(DomainName=domain)
    status = transferability["Transferability"]["Transferable"]
    assert status == "UNTRANSFERABLE", (
        f"an available (unregistered) domain must not be transferable, got {status!r}"
    )
    expected_message = (
        f"The domain {domain} isn't registered. Register the domain first and then try again."
    )
    assert transferability["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {transferability['Message']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
