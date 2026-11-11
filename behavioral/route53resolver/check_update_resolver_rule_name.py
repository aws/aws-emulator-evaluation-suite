"""update-resolver-rule-name."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-resolver-rule-name"
GROUP = 'resolver-rule'
SERVICES = ['route53resolver']

def _wait_until(probe, timeout_s=120.0, interval_s=2.0):
    """Poll probe() until truthy; raise when the deadline passes first."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    raise AssertionError(f"teardown condition not met within {timeout_s}s")


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
    """UpdateResolverRule replaces the rule's Name and bumps ModificationTime."""
    r53 = ctx.client("route53resolver")
    domain_name = f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal."
    rule = r53.create_resolver_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-rr-before-"),
        RuleType="SYSTEM",
        DomainName=domain_name,
    )["ResolverRule"]
    rule_id = rule["Id"]
    ctx.on_cleanup(lambda x=rule_id: _delete_resolver_rule(r53, x))
    def rule_status():
        return r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]["Status"]

    _poll(rule_status, lambda s: s == "COMPLETE", timeout_s=60, interval_s=2)

    before_modification_time = r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"][
        "ModificationTime"
    ]

    new_name = ctx.unique_name("sim2real-behav-rr-after-")
    r53.update_resolver_rule(ResolverRuleId=rule_id, Config={"Name": new_name})

    def rule_name():
        return r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"].get("Name")

    _poll(
        rule_name,
        lambda n: n == new_name,
        timeout_s=60,
        interval_s=2,
        description="UpdateResolverRule renamed the rule",
    )

    # The immutable DomainName must NOT have changed.
    after = r53.get_resolver_rule(ResolverRuleId=rule_id)["ResolverRule"]
    assert after["DomainName"].rstrip(".").lower() == domain_name.rstrip(".").lower(), (
        f"DomainName changed unexpectedly: {after['DomainName']} != {domain_name}"
    )
    assert after["RuleType"] == "SYSTEM", f"RuleType changed unexpectedly: {after['RuleType']}"
    assert after["ModificationTime"] != before_modification_time, (
        "UpdateResolverRule did not bump ModificationTime: "
        f"before={before_modification_time!r} after={after['ModificationTime']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
