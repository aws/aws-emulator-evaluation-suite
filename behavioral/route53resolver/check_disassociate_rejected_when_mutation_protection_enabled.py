"""disassociate-rejected-when-mutation-protection-enabled."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-rejected-when-mutation-protection-enabled"
GROUP = "e2e"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateFirewallRuleGroup is refused with ValidationException while MutationProtection is
    ENABLED and the association stays COMPLETE; once it is DISABLED the same call succeeds, as does
    disassociating an unprotected association of the same rule group.
    """
    r53r = ctx.client("route53resolver")
    trace_root = _traced(r53r)
    ec2 = ctx.client("ec2")

    rule_group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-mp-frg-req-"),
        Name=ctx.unique_name("sim2real-mp-frg-")[:64],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: r53r.delete_firewall_rule_group(FirewallRuleGroupId=rule_group_id))

    protected_vpc = ec2.create_vpc(CidrBlock="10.84.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=protected_vpc))
    open_vpc = ec2.create_vpc(CidrBlock="10.85.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=open_vpc))

    protected_assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-mp-assoc-req-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=protected_vpc,
        Priority=200,
        Name=ctx.unique_name("sim2real-mp-assoc-")[:64],
        MutationProtection="ENABLED",
    )["FirewallRuleGroupAssociation"]["Id"]

    def _unlock_and_remove():
        # Retry while an in-flight update holds the association, then wait for it to go:
        # the rule group delete that runs next is refused while it is still associated.
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            try:
                assoc = r53r.get_firewall_rule_group_association(
                    FirewallRuleGroupAssociationId=protected_assoc_id
                )["FirewallRuleGroupAssociation"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            try:
                if assoc["MutationProtection"] == "ENABLED":
                    r53r.update_firewall_rule_group_association(
                        FirewallRuleGroupAssociationId=protected_assoc_id,
                        MutationProtection="DISABLED",
                    )
                elif assoc["Status"] == "COMPLETE":
                    r53r.disassociate_firewall_rule_group(
                        FirewallRuleGroupAssociationId=protected_assoc_id
                    )
            except ClientError as err:
                if err.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
            time.sleep(5.0)
        raise AssertionError(f"association {protected_assoc_id} was not removed within 300s")

    ctx.on_cleanup(_unlock_and_remove)

    _wait_for_association_status(ctx, protected_assoc_id, "COMPLETE")

    code, message = _client_error(
        lambda: r53r.disassociate_firewall_rule_group(
            FirewallRuleGroupAssociationId=protected_assoc_id
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "[RSLVR-02307] The DNS Firewall rule group association is under mutation protection. "
        f'Remove the mutation protection and try again. Trace Id: "{trace_root}"'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    surviving = r53r.get_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=protected_assoc_id
    )["FirewallRuleGroupAssociation"]
    assert surviving["Status"] != "DELETING", surviving["Status"]
    assert surviving["MutationProtection"] == "ENABLED", surviving["MutationProtection"]

    # Restore: disabling MutationProtection must then permit the identical disassociate
    # call to succeed against the same association that was just rejected.
    r53r.update_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=protected_assoc_id,
        MutationProtection="DISABLED",
    )
    _wait_for_association_status(ctx, protected_assoc_id, "COMPLETE")
    unlocked = r53r.get_firewall_rule_group_association(
        FirewallRuleGroupAssociationId=protected_assoc_id
    )["FirewallRuleGroupAssociation"]
    assert unlocked["MutationProtection"] == "DISABLED", unlocked["MutationProtection"]

    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=protected_assoc_id)
    protected_gone_code, _ = _wait_refused(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=protected_assoc_id
        ),
        timeout_s=60,
        interval_s=3,
    )
    assert protected_gone_code == "ResourceNotFoundException", (
        f"expected the previously-protected association to disassociate cleanly once "
        f"MutationProtection was disabled, got {protected_gone_code!r}"
    )

    open_assoc_id = r53r.associate_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-mp-open-req-"),
        FirewallRuleGroupId=rule_group_id,
        VpcId=open_vpc,
        Priority=300,
        Name=ctx.unique_name("sim2real-mp-open-")[:64],
        MutationProtection="DISABLED",
    )["FirewallRuleGroupAssociation"]["Id"]

    def _remove_open():
        try:
            r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=open_assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        _wait_refused(
            lambda: r53r.get_firewall_rule_group_association(
                FirewallRuleGroupAssociationId=open_assoc_id
            ),
            timeout_s=300,
            interval_s=5,
        )

    ctx.on_cleanup(_remove_open)
    _wait_for_association_status(ctx, open_assoc_id, "COMPLETE")

    r53r.disassociate_firewall_rule_group(FirewallRuleGroupAssociationId=open_assoc_id)
    gone_code, _ = _wait_refused(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=open_assoc_id
        ),
        timeout_s=60,
        interval_s=3,
    )
    assert gone_code == "ResourceNotFoundException", (
        f"expected the unprotected sibling association to disassociate cleanly, got {gone_code!r}"
    )


def _wait_for_association_status(ctx, assoc_id: str, expected: str) -> None:
    r53r = ctx.client("route53resolver")
    status = _poll_until(
        lambda: r53r.get_firewall_rule_group_association(
            FirewallRuleGroupAssociationId=assoc_id
        )["FirewallRuleGroupAssociation"]["Status"],
        lambda s: s in ("COMPLETE", "FAILED"),
        timeout_s=300,
        interval_s=3,
    )
    assert status == expected, status


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


def _wait_refused(fn, *, timeout_s: float, interval_s: float):
    """Retry fn() until AWS refuses it; return (code, message); raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"the call still succeeded after {timeout_s}s")
        time.sleep(interval_s)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
