"""firewall-domain-list-all-numeric-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-domain-list-all-numeric-name-rejected"
GROUP = "representation"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFirewallDomainList rejects an all-numeric Name with ValidationException (the
    Name pattern explicitly forbids a name that consists of only digits), the rejected list
    is never created, and a normal alphanumeric name in the same call sequence succeeds."""
    r53r = ctx.client("route53resolver")

    bad_name = "1234567890"
    code, message = _client_error(
        lambda: r53r.create_firewall_domain_list(
            CreatorRequestId=ctx.unique_name("sim2real-fwdl-badname-req-"),
            Name=bad_name,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "(?!^[0-9]+$)([a-zA-Z0-9\\-_' ']+)"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    listed = r53r.list_firewall_domain_lists().get("FirewallDomainLists", [])
    assert all(item["Name"] != bad_name for item in listed), (
        "an all-numeric-named domain list was created despite the rejection"
    )

    # Positive control: a normal name in the same file succeeds.
    good_name = ctx.unique_name("sim2real-fwdl-goodname-")[:64]
    good_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-fwdl-goodname-req-"),
        Name=good_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=good_id)))

    fetched = r53r.get_firewall_domain_list(FirewallDomainListId=good_id)["FirewallDomainList"]
    assert fetched["Name"] == good_name, (
        f"expected the alphanumeric control name {good_name!r} to round-trip, got {fetched['Name']!r}"
    )


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
