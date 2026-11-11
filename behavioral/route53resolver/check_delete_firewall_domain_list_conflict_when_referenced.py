"""delete-firewall-domain-list-conflict-when-referenced."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-firewall-domain-list-conflict-when-referenced"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


def _traced(client):
    """Send one caller-chosen X-Ray trace id on every call of client; return its Root.

    Route 53 Resolver ends a DNS Firewall refusal message with the caller's trace Root,
    so a fixed Root makes the whole message exact.
    """
    root = f"1-{int(time.time()):08x}-{uuid.uuid4().hex[:24]}"
    header = f"Root={root};Sampled=0"

    def _add_header(request, **_):
        request.headers["X-Amzn-Trace-Id"] = header

    client.meta.events.register("before-sign.route53resolver.*", _add_header)
    return root


def _safe_delete_rule(r53, group_id, dl_id):
    try:
        r53.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=dl_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _safe_delete_group(r53, group_id):
    try:
        r53.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _safe_delete_domain_list(r53, dl_id):
    try:
        r53.delete_firewall_domain_list(FirewallDomainListId=dl_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFirewallDomainList on a list a firewall rule references is refused with
    ConflictException and the list stays readable; after the rule and its rule group are deleted the
    same call succeeds and the list reads back as not found.
    """
    r53 = ctx.client("route53resolver")
    trace_root = _traced(r53)
    tag_spec = [{"Key": "sim2real", "Value": "behavioral"}]

    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
        Tags=tag_spec,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: _safe_delete_domain_list(r53, x))
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=tag_spec,
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: _safe_delete_group(r53, x))
    r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_id,
        Priority=100,
        Action="BLOCK",
        BlockResponse="NODATA",
        Name=ctx.unique_name("sim2real-behav-fr-"),
    )
    ctx.on_cleanup(lambda g=group_id, d=dl_id: _safe_delete_rule(r53, g, d))

    # Break exactly one thing: try to delete the domain list while a rule still references it.
    code, message = _client_error(
        lambda: r53.delete_firewall_domain_list(FirewallDomainListId=dl_id)
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected = (
        "[RSLVR-02304] The DNS Firewall domain list is associated with a DNS Firewall rule : "
        f'"{group_id}". Delete the rule and then try again. Trace Id: "{trace_root}"'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: an independent read shows the domain list survived the rejected delete.
    still_there = r53.get_firewall_domain_list(FirewallDomainListId=dl_id)["FirewallDomainList"]
    assert still_there["Id"] == dl_id, f"expected domain list {dl_id} to still exist, got {still_there!r}"

    # Restore: remove the conflicting rule and its empty rule group, then the exact same delete
    # call succeeds.
    r53.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=dl_id)
    r53.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    r53.delete_firewall_domain_list(FirewallDomainListId=dl_id)

    # Gone and unusable: deletion is asynchronous (the domain list passes through DELETING),
    # so poll a bounded window for the independent read to return the specific not-found error.
    deadline = time.monotonic() + 60.0
    deleted_code = deleted_message = None
    while time.monotonic() < deadline:
        try:
            r53.get_firewall_domain_list(FirewallDomainListId=dl_id)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            deleted_code, deleted_message = err.get("Code"), err.get("Message")
            if deleted_code == "ResourceNotFoundException":
                break
        time.sleep(2)
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete within 60s, got {deleted_code}"
    )
    gone_message = f'[RSLVR-02025] Can’t find the resource with ID "{dl_id}". Trace Id: "{trace_root}"'
    assert deleted_message == gone_message, (
        f"expected message {gone_message!r}, got {deleted_message!r}"
    )

    # Unusable: a mutation on the dead id also fails with the same not-found error.
    mutate_code, mutate_message = _client_error(
        lambda: r53.delete_firewall_domain_list(FirewallDomainListId=dl_id)
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on repeat delete, got {mutate_code}"
    )
    assert mutate_message == gone_message, (
        f"expected message {gone_message!r}, got {mutate_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
