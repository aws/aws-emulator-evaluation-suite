"""domain-scoped-operations-require-domain-in-account."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-scoped-operations-require-domain-in-account"
GROUP = "domain-existence"
SERVICES = ["route53domains"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every domain-scoped operation refuses a domain absent from the account with the
    same InvalidInput message, while a non-scoped call on the same name still succeeds.
    """
    r53d = ctx.client("route53domains", region="us-east-1")
    name = ctx.unique_name("sim2real-behav-r53d-missing-") + ".com"
    expected_message = f"Invalid request. Problems: Domain {name} not found in account."

    calls = {
        "GetDomainDetail": lambda: r53d.get_domain_detail(DomainName=name),
        "ListTagsForDomain": lambda: r53d.list_tags_for_domain(DomainName=name),
        "GetContactReachabilityStatus": lambda: r53d.get_contact_reachability_status(
            domainName=name
        ),
        "DisableDomainTransferLock": lambda: r53d.disable_domain_transfer_lock(DomainName=name),
        "DeleteDomain": lambda: r53d.delete_domain(DomainName=name),
    }
    for op_name, call in calls.items():
        code, message = _error(call)
        assert code == "InvalidInput", f"{op_name}: expected InvalidInput, got {code}: {message!r}"
        assert message == expected_message, (
            f"{op_name}: expected {expected_message!r}, got {message!r}"
        )

    # Positive control: the same name is a perfectly valid argument to a call that is not
    # scoped to a domain already in the account.
    availability = r53d.check_domain_availability(DomainName=name)["Availability"]
    assert availability == "AVAILABLE", (
        f"CheckDomainAvailability for the same name {name!r} returned {availability!r}, "
        "expected AVAILABLE — the name itself is not the problem, only the missing domain is"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
