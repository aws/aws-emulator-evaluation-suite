"""create-forward-resolver-rule-requires-endpoint-and-targets."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-forward-resolver-rule-requires-endpoint-and-targets"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

FORWARD_REQUIRES_MESSAGE = (
    "[RSLVR-00706] Resolver endpoint ID and target IP are required for FORWARD type resolver rule."
)


def _delete_when_possible(fn, *, timeout_s=120.0, interval_s=5.0, **kwargs):
    """Retry a delete until it succeeds or the resource is gone; raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if "NotFound" in code or code == "ResourceNotFoundException":
                return
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"teardown {fn.__name__}({kwargs}) never succeeded; last error {last}")


def _rule_ids_for_domain(r53, domain):
    """Return ids of every resolver rule whose domain matches, following pagination."""
    wanted = domain.rstrip(".").lower()
    ids = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53.list_resolver_rules(**kwargs)
        for rule in page.get("ResolverRules", []):
            if (rule.get("DomainName") or "").rstrip(".").lower() == wanted:
                ids.append(rule["Id"])
        token = page.get("NextToken")
        if not token:
            return ids


def _expect_rejected(fn, register_cleanup):
    """Call fn(); on unexpected success, register cleanup for the created rule and raise. On
    ClientError, return its ``Error``."""
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]
    rule = resp.get("ResolverRule", {})
    register_cleanup(rule.get("Id"))
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and created ResolverRule "
        f"{rule.get('Id')!r}: {resp!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResolverRule of type FORWARD without ResolverEndpointId and TargetIps is refused with
    InvalidRequestException and creates no rule, while a SYSTEM rule for the same domain is
    created.
    """
    r53 = ctx.client("route53resolver")

    def _register_cleanup(rule_id):
        if rule_id:
            ctx.on_cleanup(
                lambda x=rule_id: _delete_when_possible(r53.delete_resolver_rule, ResolverRuleId=x)
            )

    # CONTROL: a SYSTEM rule needs no outbound endpoint, so this is a free proof that
    # CreateResolverRule works at all in this account — without it, "rejects a bare
    # FORWARD rule" would be indistinguishable from "rejects every CreateResolverRule
    # call" (no permissions, service down, etc).
    control_domain = ctx.unique_name("sim2real-behav-ctl-") + ".example.internal."
    control = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-rr-ctl-"),
        RuleType="SYSTEM",
        DomainName=control_domain,
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["ResolverRule"]
    ctx.on_cleanup(
        lambda x=control["Id"]: _delete_when_possible(r53.delete_resolver_rule, ResolverRuleId=x)
    )
    assert control["RuleType"] == "SYSTEM", control

    # BREAK: a FORWARD rule with neither ResolverEndpointId nor TargetIps.
    bare_domain = ctx.unique_name("sim2real-behav-zone-") + ".example.internal."

    def bare_forward():
        return r53.create_resolver_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            Name=ctx.unique_name("sim2real-behav-rr-"),
            RuleType="FORWARD",
            DomainName=bare_domain,
            Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        )

    err = _expect_rejected(bare_forward, _register_cleanup)
    assert err["Code"] == "InvalidRequestException", (
        f"expected InvalidRequestException for a FORWARD rule with no endpoint/targets, "
        f"got {err}"
    )
    assert err["Message"] == FORWARD_REQUIRES_MESSAGE, err

    # EFFECT ABSENT: the rejected rule was never stored.
    leaked = _rule_ids_for_domain(r53, bare_domain)
    assert leaked == [], (
        f"a rejected bare FORWARD rule must not be stored; found {leaked} for {bare_domain}"
    )

    # BREAK (second class): TargetIps supplied but still no ResolverEndpointId.
    targets_domain = ctx.unique_name("sim2real-behav-zone-") + ".example.internal."

    def targets_without_endpoint():
        return r53.create_resolver_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            Name=ctx.unique_name("sim2real-behav-rr-"),
            RuleType="FORWARD",
            DomainName=targets_domain,
            TargetIps=[{"Ip": "10.1.2.6", "Port": 53}],
            Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        )

    err2 = _expect_rejected(targets_without_endpoint, _register_cleanup)
    assert err2["Code"] == "InvalidRequestException", (
        f"expected InvalidRequestException for a FORWARD rule with targets but no "
        f"ResolverEndpointId, got {err2}"
    )
    assert err2["Message"] == FORWARD_REQUIRES_MESSAGE, err2

    # EFFECT ABSENT for the second class too.
    leaked2 = _rule_ids_for_domain(r53, targets_domain)
    assert leaked2 == [], (
        f"a rejected FORWARD rule with targets but no endpoint must not be stored; "
        f"found {leaked2} for {targets_domain}"
    )

    # CONTROL STILL WORKS: the valid SYSTEM rule survives both rejected attempts
    # unaffected.
    reread = r53.get_resolver_rule(ResolverRuleId=control["Id"])["ResolverRule"]
    assert reread["RuleType"] == "SYSTEM", reread
    assert not reread.get("TargetIps"), (
        f"the control rule must still carry no TargetIps, got {reread.get('TargetIps')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
