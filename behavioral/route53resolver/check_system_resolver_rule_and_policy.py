"""system-resolver-rule-and-policy."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "system-resolver-rule-and-policy"
GROUP = 'resolver-rule'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

def _err_code(fn):
    """Call fn(); return botocore Error.Code if a ClientError is raised, else None."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_until(probe, timeout_s=120.0, interval_s=2.0):
    """Poll probe() until truthy; raise when the deadline passes first."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    raise AssertionError(f"teardown condition not met within {timeout_s}s")


def _account_id(ctx):
    return ctx.account


def _delete_resolver_rule(r53, rule_id):
    """Delete the rule, retrying ResourceInUseException while an association is still being removed."""
    def _attempt():
        try:
            r53.delete_resolver_rule(ResolverRuleId=rule_id)
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                return True
            if code == "ResourceInUseException":
                return False
            raise

    _wait_until(_attempt, timeout_s=120)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A SYSTEM rule needs no endpoint or TargetIps, reaches COMPLETE, and is in ListResolverRules.

    A self-share PutResolverRulePolicy is accepted but stores nothing; Get returns an empty policy.
    """
    r53 = ctx.client("route53resolver")
    domain = f"{ctx.unique_name('sim2real-behav-sysz-')}.example.internal."
    created = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        RuleType="SYSTEM",
        DomainName=domain,
        Name=ctx.unique_name("sim2real-behav-sysrule-"),
        Tags=TAGS_KV,
    )["ResolverRule"]
    rule_id = created["Id"]
    rule_arn = created["Arn"]
    ctx.on_cleanup(lambda x=rule_id: _delete_resolver_rule(r53, x))

    assert created["RuleType"] == "SYSTEM", created
    assert not created.get("TargetIps"), f"SYSTEM rule must not carry TargetIps, got {created.get('TargetIps')}"

    _poll(
        lambda: r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]["Status"],
        lambda s: s == "COMPLETE",
        timeout_s=60,
        interval_s=2,
        description="SYSTEM resolver rule reaches COMPLETE",
    )

    seen = []
    token = None
    while True:
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        resp = r53.list_resolver_rules(**kwargs)
        seen.extend(resp["ResolverRules"])
        token = resp.get("NextToken")
        if not token:
            break
    assert any(r["Id"] == rule_id for r in seen), f"{rule_id} missing from ListResolverRules"

    account_id = _account_id(ctx)
    policy_doc = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":["{account_id}"]}},'
        '"Action":["route53resolver:GetResolverRule",'
        '"route53resolver:AssociateResolverRule",'
        '"route53resolver:DisassociateResolverRule",'
        '"route53resolver:ListResolverRules",'
        '"route53resolver:ListResolverRuleAssociations"],'
        f'"Resource":["{rule_arn}"]}}]}}'
    )
    put = r53.put_resolver_rule_policy(Arn=rule_arn, ResolverRulePolicy=policy_doc)
    assert put["ReturnValue"] is True, put

    # Real Resolver ACCEPTS the Put but stores nothing when the only principal is
    # the rule's own owner account (sharing a rule with yourself is a no-op), so
    # Get returns an empty policy document rather than echoing the input back.
    got = r53.get_resolver_rule_policy(Arn=rule_arn)["ResolverRulePolicy"]
    assert json.loads(got) == {}, f"self-share policy must store nothing, got {got}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
