"""create-firewall-rule-layers-field-validation-ahead-of-dns-view-lookup."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-layers-field-validation-ahead-of-dns-view-lookup"
GROUP = "validation-ordering"
SERVICES = ["route53globalresolver"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _client(ctx):
    """route53globalresolver serves its control plane only in us-east-2, at an api.aws host
    botocore does not resolve by default; ctx.service_url names that host on real AWS and the
    target's endpoint otherwise."""
    return ctx.client(
        "route53globalresolver",
        region="us-east-2",
        endpoint_url=ctx.service_url("https://route53globalresolver.us-east-2.api.aws"),
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFirewallRule checks the request shape, then a cross-field business rule, then
    another cross-field rule, all before it ever looks up the dnsViewId it was given — a
    well-formed but absent dnsViewId never surfaces a lookup failure once a field is invalid.
    """
    client = _client(ctx)
    missing_dns_view_id = ctx.unique_name("sim2real-behav-dv-")
    missing_domain_list_id = ctx.unique_name("sim2real-behav-fdl-")

    malformed_dns_view_id = "not an id !!!"
    code, message = _error(
        lambda: client.create_firewall_rule(
            dnsViewId=malformed_dns_view_id, name="sim2real-rule", action="BLOCK"
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected_pattern_message = (
        f"1 validation error detected: Value '{malformed_dns_view_id}' at 'dnsViewId' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [-.a-zA-Z0-9]+"
    )
    assert message == expected_pattern_message, f"unexpected message {message!r}"

    code, message = _error(
        lambda: client.create_firewall_rule(
            dnsViewId=missing_dns_view_id, name="sim2real-rule", action="BLOCK"
        )
    )
    assert code == "ValidationException", (
        f"a rule naming no target (neither FirewallDomainListId nor DnsAdvancedProtection) must "
        f"fail that cross-field rule before dnsViewId is ever looked up, got {code}: {message!r}"
    )
    assert message == (
        "[GR-ERR04003] Input should contain exactly one of FirewallDomainListId or "
        "DnsAdvancedProtection."
    ), f"unexpected message {message!r}"

    code, message = _error(
        lambda: client.create_firewall_rule(
            dnsViewId=missing_dns_view_id,
            firewallDomainListId=missing_domain_list_id,
            name="sim2real-rule",
            action="BLOCK",
        )
    )
    assert code == "ValidationException", (
        f"a BLOCK rule with no blockResponse must fail that rule too, still before dnsViewId "
        f"lookup, got {code}: {message!r}"
    )
    assert message == "[GR-ERR04001] BlockResponse must be provided if Action is BLOCK.", (
        f"unexpected message {message!r}"
    )

    # Positive control: the client, credentials and us-east-2 control-plane endpoint actually
    # work, so the three rejections above are not an artifact of a universally broken call.
    listed = client.list_access_sources()
    assert "accessSources" in listed, f"ListAccessSources response missing its key: {listed!r}"
    assert isinstance(listed["accessSources"], list), (
        f"accessSources must be a list, got {listed['accessSources']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
