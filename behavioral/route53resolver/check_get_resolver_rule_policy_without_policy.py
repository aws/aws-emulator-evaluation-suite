"""get-resolver-rule-policy-without-policy."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resolver-rule-policy-without-policy"
GROUP = 'resource-policy'
SERVICES = ['route53resolver']

def _wait_until(probe, timeout_s=120.0, interval_s=2.0):
    """Poll probe() until truthy; raise when the deadline passes first."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    raise AssertionError(f"teardown condition not met within {timeout_s}s")


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
    """GetResolverRulePolicy on a never-shared rule returns 200 with ResolverRulePolicy "{}".

    The field is the literal empty-object document, not absent and not an error.
    """
    r53 = ctx.client("route53resolver")
    import json

    rule = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-rr-"),
        RuleType="SYSTEM",
        DomainName=f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal.",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )["ResolverRule"]
    rule_arn = rule["Arn"]
    ctx.on_cleanup(lambda x=rule["Id"]: _delete_resolver_rule(r53, x))
    resp = r53.get_resolver_rule_policy(Arn=rule_arn)
    policy = resp.get("ResolverRulePolicy")
    assert isinstance(policy, str), f"ResolverRulePolicy must be a string, got {policy!r}"
    assert json.loads(policy) == {}, (
        f"a rule that was never shared must report an empty policy document, got {policy!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
