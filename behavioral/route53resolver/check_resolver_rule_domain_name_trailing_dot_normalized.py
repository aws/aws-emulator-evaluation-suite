"""resolver-rule-domain-name-trailing-dot-normalized."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resolver-rule-domain-name-trailing-dot-normalized"
GROUP = 'resolver-rule'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


def _poll(probe, predicate, *, timeout_s=60, interval_s=2.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _find_listed_rule(r53, rule_id):
    """Return the ListResolverRules projection of one rule, following pagination."""
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = r53.list_resolver_rules(**kwargs)
        for rule in page.get("ResolverRules", []):
            if rule.get("Id") == rule_id:
                return rule
        token = page.get("NextToken")
        if not token:
            return None


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A rule DomainName given with or without a trailing dot is stored as the same fully-qualified
    name ending in a dot, and Create, Get and List all project that identical value.
    """
    r53 = ctx.client("route53resolver")
    base = ctx.unique_name("d-") + ".sim2real-behav.example.com"

    # SYSTEM rules need no ResolverEndpointId, so no billable ENI is created.
    dotless = base
    rule1 = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-rr-a-"),
        RuleType="SYSTEM",
        DomainName=dotless,
        Tags=TAGS_KV,
    )["ResolverRule"]
    ctx.on_cleanup(
        lambda x=rule1["Id"]: _delete_when_possible(r53.delete_resolver_rule, ResolverRuleId=x)
    )

    created_name = rule1["DomainName"]
    assert created_name.rstrip(".").lower() == dotless.lower(), (
        f"the stored domain must be {dotless!r} modulo canonicalisation, got {created_name!r}"
    )
    assert created_name.endswith("."), (
        "Resolver canonicalises a rule domain to a fully-qualified name with a trailing "
        f"dot; CreateResolverRule projected {created_name!r} for input {dotless!r}"
    )

    got = _poll(
        lambda: r53.get_resolver_rule(ResolverRuleId=rule1["Id"])["ResolverRule"],
        lambda r: r.get("Status") in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=3,
        description="rule 1 reaches a terminal status",
    )
    assert got["Status"] == "COMPLETE", got
    assert got["DomainName"] == created_name, (
        f"GetResolverRule projected {got['DomainName']!r}, Create projected {created_name!r}"
    )
    assert got["RuleType"] == "SYSTEM", got
    assert got.get("TargetIps") in (None, []), (
        f"a SYSTEM rule must carry no TargetIps, got {got.get('TargetIps')!r}"
    )

    listed = _find_listed_rule(r53, rule1["Id"])
    assert listed is not None, f"rule {rule1['Id']} absent from ListResolverRules"
    assert listed["DomainName"] == created_name, (
        f"ListResolverRules projected {listed['DomainName']!r}, "
        f"Get projected {created_name!r}"
    )

    dotted = base + "."
    rule2 = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-rr-b-"),
        RuleType="SYSTEM",
        DomainName=dotted,
        Tags=TAGS_KV,
    )["ResolverRule"]
    ctx.on_cleanup(
        lambda x=rule2["Id"]: _delete_when_possible(r53.delete_resolver_rule, ResolverRuleId=x)
    )
    assert rule2["DomainName"] == created_name, (
        f"{dotted!r} and {dotless!r} are the same domain but were stored as "
        f"{rule2['DomainName']!r} and {created_name!r}"
    )
    assert rule2["Id"] != rule1["Id"], (
        "two distinct CreateResolverRule calls with distinct CreatorRequestIds must "
        f"yield distinct rules, both returned {rule1['Id']}"
    )

    got2 = _poll(
        lambda: r53.get_resolver_rule(ResolverRuleId=rule2["Id"])["ResolverRule"],
        lambda r: r.get("Status") in ("COMPLETE", "FAILED"),
        timeout_s=90,
        interval_s=3,
        description="rule 2 reaches a terminal status",
    )
    assert got2["Status"] == "COMPLETE", got2
    assert got2["DomainName"] == created_name, (
        f"GetResolverRule for the dotted-input rule projected {got2['DomainName']!r}, "
        f"expected the same canonical value as rule 1: {created_name!r}"
    )

    listed2 = _find_listed_rule(r53, rule2["Id"])
    assert listed2 is not None, f"rule {rule2['Id']} absent from ListResolverRules"
    assert listed2["DomainName"] == created_name, (
        f"ListResolverRules projected {listed2['DomainName']!r} for the dotted-input "
        f"rule, expected the same canonical value as rule 1: {created_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
