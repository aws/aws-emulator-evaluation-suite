"""creator-request-id-idempotency-token-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "creator-request-id-idempotency-token-preserved"
GROUP = "representation"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CreatorRequestId with colons, spaces and a leading '#' is returned unchanged by
    GetResolverRule, and each of two rules keeps its own distinct value.
    """
    r53r = ctx.client("route53resolver")

    creator_request_id_a = ctx.unique_name("sim2real-crid-a-") + ":2024-01-01T00:00:00Z #alpha"
    creator_request_id_b = ctx.unique_name("sim2real-crid-b-") + ":2024-01-01T00:00:00Z #beta"

    # RuleType SYSTEM needs neither TargetIps nor a ResolverEndpointId, so this exercises
    # CreatorRequestId round-tripping without provisioning VPC/endpoint infrastructure.
    rule_a_id = r53r.create_resolver_rule(
        CreatorRequestId=creator_request_id_a,
        Name=ctx.unique_name("sim2real-crid-rule-a-")[:64],
        RuleType="SYSTEM",
        DomainName="apex-a.sim2real-crid.test.",
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_a_id)))

    rule_b_id = r53r.create_resolver_rule(
        CreatorRequestId=creator_request_id_b,
        Name=ctx.unique_name("sim2real-crid-rule-b-")[:64],
        RuleType="SYSTEM",
        DomainName="apex-b.sim2real-crid.test.",
    )["ResolverRule"]["Id"]
    ctx.on_cleanup(lambda: _safe(lambda: r53r.delete_resolver_rule(ResolverRuleId=rule_b_id)))

    fetched_a = r53r.get_resolver_rule(ResolverRuleId=rule_a_id)["ResolverRule"]
    fetched_b = r53r.get_resolver_rule(ResolverRuleId=rule_b_id)["ResolverRule"]

    assert fetched_a["CreatorRequestId"] == creator_request_id_a, (
        f"expected {creator_request_id_a!r}, got {fetched_a['CreatorRequestId']!r}"
    )
    assert fetched_b["CreatorRequestId"] == creator_request_id_b, (
        f"expected {creator_request_id_b!r}, got {fetched_b['CreatorRequestId']!r}"
    )
    assert fetched_a["CreatorRequestId"] != fetched_b["CreatorRequestId"], (
        f"rule A and rule B CreatorRequestId collapsed to the same value "
        f"{fetched_a['CreatorRequestId']!r}; expected distinct {creator_request_id_a!r} "
        f"and {creator_request_id_b!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
