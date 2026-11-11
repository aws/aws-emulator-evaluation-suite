"""firewall-domain-unicode-wildcard-round-trip."""
from __future__ import annotations

import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-domain-unicode-wildcard-round-trip"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """Mixed-case punycode and wildcard-prefixed domains added to a firewall domain list are listed
    back lowercased with a trailing dot, keeping the wildcard prefix and the punycode encoding.
    """
    r53r = ctx.client("route53resolver")

    domain_list = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-r53r-dl-"),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["FirewallDomainList"]
    domain_list_id = domain_list["Id"]
    ctx.on_cleanup(lambda: _safe_delete(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id)))

    suffix = uuid.uuid4().hex[:8]
    punycode_wildcard = f"*.xn--mnchen-3ya-{suffix}.example"
    mixed_case_domain = f"CaseTest-{suffix}.Example"

    r53r.update_firewall_domains(
        FirewallDomainListId=domain_list_id,
        Operation="ADD",
        Domains=[punycode_wildcard, mixed_case_domain],
    )
    _poll_until(
        lambda: r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)[
            "FirewallDomainList"
        ]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=60.0,
        interval_s=2.0,
    )

    domains = r53r.list_firewall_domains(FirewallDomainListId=domain_list_id)["Domains"]

    # Route 53 Resolver DNS Firewall normalizes stored domains to lowercase
    # and appends a trailing FQDN dot -- but preserves the wildcard prefix and the exact
    # punycode (xn--) encoding unchanged. Assert against that normalized form.
    expected_punycode_wildcard = punycode_wildcard.lower() + "."
    expected_mixed_case_domain = mixed_case_domain.lower() + "."

    assert expected_punycode_wildcard in domains, (
        f"punycode wildcard domain {expected_punycode_wildcard!r} not found, got {domains}"
    )
    assert expected_mixed_case_domain in domains, (
        f"lowercased domain {expected_mixed_case_domain!r} not found, got {domains}"
    )
    assert len(domains) == 2, f"expected exactly 2 domains, got {domains}"

    # The wildcard prefix and punycode encoding are preserved exactly, just lowercased.
    stored_wildcard = next(d for d in domains if d.startswith("*."))
    assert stored_wildcard.startswith("*.xn--mnchen-3ya-"), (
        f"wildcard prefix or punycode encoding not preserved: {stored_wildcard!r}"
    )

    # Deletes prove gone and unusable: an independent read 404s (deletion is itself
    # eventually consistent, so this is a bounded poll, not an immediate assert), and a
    # mutation on the dead id also fails with the same specific error.
    r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id)

    _poll_until(
        lambda: _domain_list_gone(r53r, domain_list_id),
        lambda gone: gone,
        timeout_s=60.0,
        interval_s=2.0,
    )

    code, message = _error(
        lambda: r53r.update_firewall_domains(
            FirewallDomainListId=domain_list_id, Operation="ADD", Domains=["still-there.example"]
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating the deleted list, got {code}"
    )
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{domain_list_id}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _domain_list_gone(r53r, domain_list_id: str) -> bool:
    try:
        r53r.get_firewall_domain_list(FirewallDomainListId=domain_list_id)
        return False
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException"


def _safe_delete(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
