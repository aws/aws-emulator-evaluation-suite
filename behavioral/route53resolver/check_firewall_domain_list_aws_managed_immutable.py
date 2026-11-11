"""firewall-domain-list-aws-managed-immutable."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "firewall-domain-list-aws-managed-immutable"
GROUP = "server-side"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AWS-managed firewall domain lists (DNS Firewall threat-intel lists) cannot be
    mutated or deleted by the caller -- UpdateFirewallDomains and DeleteFirewallDomainList
    against a managed list are rejected server-side, not merely by client-side tooling."""
    r53r = ctx.client("route53resolver")

    managed = _find_managed_domain_list(r53r)
    if managed is None:
        raise AssertionError(
            "no AWS-managed firewall domain list (ManagedOwnerName set) is visible in "
            "ListFirewallDomainLists for this account/region -- DNS Firewall managed threat "
            "lists may require the account's first-time DNS Firewall activation to appear; "
            "activate DNS Firewall once to close this gap"
        )
    managed_id = managed["Id"]

    update_code, update_message = _error(
        lambda: r53r.update_firewall_domains(
            FirewallDomainListId=managed_id,
            Operation="ADD",
            Domains=["sim2real-should-not-land.example."],
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateFirewallDomains against the AWS-managed list {managed_id} to be "
        f"rejected ResourceNotFoundException, got {update_code!r}"
    )
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{managed_id}".'
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"

    list_code, list_message = _error(lambda: r53r.list_firewall_domains(FirewallDomainListId=managed_id))
    assert list_code == "AccessDeniedException", (
        f"expected ListFirewallDomains against the AWS-managed list {managed_id} to be "
        f"rejected AccessDeniedException, got {list_code!r}"
    )
    expected = (
        "You don't have a permission to list the domains inside a Route 53 Resolver DNS Firewall "
        "managed list."
    )
    assert list_message == expected, f"expected message {expected!r}, got {list_message!r}"
    domains_after = _list_all_domains_tolerant(r53r, managed_id)
    assert "sim2real-should-not-land.example." not in domains_after, (
        f"the domain injected by the rejected UpdateFirewallDomains call landed in "
        f"{managed_id}: {domains_after!r}"
    )

    delete_code, delete_message = _error(
        lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=managed_id)
    )
    assert delete_code == "ResourceNotFoundException", (
        f"expected DeleteFirewallDomainList against the AWS-managed list {managed_id} to be "
        f"rejected ResourceNotFoundException, got {delete_code!r}"
    )
    expected = f'[RSLVR-02025] Can\u2019t find the resource with ID "{managed_id}".'
    assert delete_message == expected, f"expected message {expected!r}, got {delete_message!r}"

    still_there = r53r.get_firewall_domain_list(FirewallDomainListId=managed_id)["FirewallDomainList"]
    assert still_there["Id"] == managed_id, (
        f"expected GetFirewallDomainList to still return {managed_id} after the rejected "
        f"delete, got {still_there.get('Id')!r}"
    )
    assert still_there["Status"] == managed["Status"], (
        f"expected the managed list's Status to be unchanged by the rejected delete "
        f"(was {managed['Status']!r}), got {still_there['Status']!r}"
    )
    assert still_there["DomainCount"] == managed["DomainCount"], (
        f"expected the managed list's DomainCount to be unchanged by the rejected update "
        f"(was {managed['DomainCount']!r}), got {still_there['DomainCount']!r}"
    )

    # Positive control: the same two operations succeed against our own, non-managed list.
    own_list = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-fdl-crid-"),
        Name=ctx.unique_name("sim2real-r53r-fdl-"),
        Tags=[{"Key": "env", "Value": "behavioral-test"}],
    )["FirewallDomainList"]
    own_id = own_list["Id"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=own_id))
    r53r.update_firewall_domains(
        FirewallDomainListId=own_id, Operation="ADD", Domains=["sim2real-owned.example."]
    )
    own_domains = _list_all_domains(r53r, own_id)
    assert "sim2real-owned.example." in own_domains, (
        f"expected UpdateFirewallDomains against our own non-managed list {own_id} to succeed "
        f"and be visible in ListFirewallDomains, got {own_domains!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], _without_trace_id(err.response["Error"].get("Message"))
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _find_managed_domain_list(r53r) -> dict[str, Any] | None:
    token = None
    while True:
        kwargs: dict[str, Any] = {}
        if token:
            kwargs["NextToken"] = token
        resp = r53r.list_firewall_domain_lists(**kwargs)
        for summary in resp.get("FirewallDomainLists", []):
            detail = r53r.get_firewall_domain_list(FirewallDomainListId=summary["Id"])["FirewallDomainList"]
            if detail.get("ManagedOwnerName"):
                return detail
        token = resp.get("NextToken")
        if not token:
            return None


def _list_all_domains(r53r, firewall_domain_list_id: str) -> list[str]:
    out: list[str] = []
    token = None
    while True:
        kwargs: dict[str, Any] = {"FirewallDomainListId": firewall_domain_list_id}
        if token:
            kwargs["NextToken"] = token
        resp = r53r.list_firewall_domains(**kwargs)
        out.extend(resp.get("Domains", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _list_all_domains_tolerant(r53r, firewall_domain_list_id: str) -> list[str]:
    """A managed list rejects ListFirewallDomains with AccessDeniedException (a different
    code than the ResourceNotFoundException its writes return) -- treat either denial as
    "no domains visible" rather than a hard failure, since either way the injected domain
    cannot have landed."""
    from botocore.exceptions import ClientError

    try:
        return _list_all_domains(r53r, firewall_domain_list_id)
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "AccessDeniedException"):
            return []
        raise


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
