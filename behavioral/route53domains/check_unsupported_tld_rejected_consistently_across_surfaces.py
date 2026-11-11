"""unsupported-tld-rejected-consistently-across-surfaces."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unsupported-tld-rejected-consistently-across-surfaces"
GROUP = "domain-research"
SERVICES = ["route53domains"]

_UNSUPPORTED_TLD = "zzinvalidtld"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unsupported TLD is rejected the same way by every operation that takes one, and
    the API keeps serving a supported TLD afterward.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_CheckDomainAvailability.html
    """
    r53 = ctx.client("route53domains", region="us-east-1")
    domain = f"{ctx.unique_name('sim2real-behav-r53d-')}.{_UNSUPPORTED_TLD}"
    expected_message = f"The {_UNSUPPORTED_TLD} TLD is not supported"

    code, message = _error(lambda: r53.check_domain_availability(DomainName=domain))
    assert code == "UnsupportedTLD", (
        f"CheckDomainAvailability: expected UnsupportedTLD, got {code}: {message!r}"
    )
    assert message == expected_message, f"CheckDomainAvailability: unexpected message {message!r}"

    code, message = _error(lambda: r53.check_domain_transferability(DomainName=domain))
    assert code == "UnsupportedTLD", (
        f"CheckDomainTransferability: expected UnsupportedTLD, got {code}: {message!r}"
    )
    assert message == expected_message, (
        f"CheckDomainTransferability: unexpected message {message!r}"
    )

    code, message = _error(lambda: r53.list_prices(Tld=_UNSUPPORTED_TLD))
    assert code == "UnsupportedTLD", f"ListPrices: expected UnsupportedTLD, got {code}: {message!r}"
    assert message == expected_message, f"ListPrices: unexpected message {message!r}"

    # Positive control: the three rejections above left the API itself unaffected.
    control_domain = f"{ctx.unique_name('sim2real-behav-r53d-')}.com"
    availability = r53.check_domain_availability(DomainName=control_domain)["Availability"]
    assert availability == "AVAILABLE", (
        f"after the unsupported-TLD rejections, a supported-TLD request for {control_domain!r} "
        f"returned {availability!r} instead of AVAILABLE"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
