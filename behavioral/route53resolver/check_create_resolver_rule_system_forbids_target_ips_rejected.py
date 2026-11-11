"""create-resolver-rule-system-forbids-target-ips-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resolver-rule-system-forbids-target-ips-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SYSTEM resolver rule with TargetIps is rejected and creates nothing, while the same rule
    without targets is accepted and unchanged; SYSTEM means Resolver's own recursive resolution,
    which a forwarding target would contradict.
    """
    r53 = ctx.client("route53resolver")
    domain = ctx.unique_name("sys-") + ".sim2real-behav.example.com"

    good_name = ctx.unique_name("sim2real-behav-rr-ok-")
    good = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=good_name,
        RuleType="SYSTEM",
        DomainName=domain,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["ResolverRule"]
    ctx.on_cleanup(
        lambda x=good["Id"]: _delete_when_possible(r53.delete_resolver_rule, ResolverRuleId=x)
    )
    assert good["RuleType"] == "SYSTEM", good
    assert not good.get("TargetIps"), (
        f"a SYSTEM rule must project no TargetIps, got {good.get('TargetIps')!r}"
    )
    assert not good.get("ResolverEndpointId"), (
        f"a SYSTEM rule must project no ResolverEndpointId, got "
        f"{good.get('ResolverEndpointId')!r}"
    )

    # No ResolverEndpointId, so TargetIps is the sole defect and no billable endpoint is needed.
    created = {}
    bad_domain = ctx.unique_name("sysbad-") + ".sim2real-behav.example.com"

    def system_with_targets():
        resp = r53.create_resolver_rule(
            CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
            Name=ctx.unique_name("sim2real-behav-rr-bad-"),
            RuleType="SYSTEM",
            DomainName=bad_domain,
            TargetIps=[{"Ip": "10.1.2.6", "Port": 53}],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        created["id"] = resp["ResolverRule"]["Id"]
        return resp

    try:
        code, message = _client_error(system_with_targets)
    finally:
        if created.get("id"):
            # Created despite the expected refusal; register teardown before the assert fails.
            ctx.on_cleanup(
                lambda x=created["id"]: _delete_when_possible(
                    r53.delete_resolver_rule, ResolverRuleId=x
                )
            )
    assert code == "InvalidRequestException", (
        "expected InvalidRequestException (the RSLVR cross-member constraint class, "
        "as in the FORWARD mirror check) for a SYSTEM rule carrying TargetIps, got "
        f"{code}"
    )
    expected_message = (
        "[RSLVR-00707] Cannot specify resolver endpoint ID and target IP for SYSTEM type "
        "resolver rule."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    leaked = _rule_ids_for_domain(r53, bad_domain)
    assert leaked == [], (
        f"a rejected SYSTEM-with-TargetIps rule must not be stored; found {leaked} "
        f"for {bad_domain}"
    )

    reread = r53.get_resolver_rule(ResolverRuleId=good["Id"])["ResolverRule"]
    assert reread["Name"] == good_name, reread
    assert reread["RuleType"] == "SYSTEM", reread
    assert not reread.get("TargetIps"), (
        f"the control rule must still carry no TargetIps, got {reread.get('TargetIps')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
