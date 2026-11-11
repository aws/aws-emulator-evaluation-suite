"""create-resolver-rule-duplicate-creator-request-id."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resolver-rule-duplicate-creator-request-id"
GROUP = 'overly-permissive'
SERVICES = ['route53resolver']

def _wait_until(probe, timeout_s=120.0, interval_s=2.0):
    """Poll probe() until truthy; raise when the deadline passes first."""
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    raise AssertionError(f"teardown condition not met within {timeout_s}s")


def _client_error(fn):
    """Call fn(), which AWS refuses; return the (code, message) of its ClientError."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call succeeded; expected AWS to refuse it with a ClientError")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatorRequestId is a dedup token: reusing it on CreateResolverRule with different
    content is rejected as a conflict, never answered with the existing or a new rule."""
    r53 = ctx.client("route53resolver")
    creator_request_id = ctx.unique_name("sim2real-behav-cr-idem-")
    domain_name = f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal."

    rule = r53.create_resolver_rule(
        CreatorRequestId=creator_request_id,
        Name=ctx.unique_name("sim2real-behav-rr-"),
        RuleType="SYSTEM",
        DomainName=domain_name,
    )["ResolverRule"]
    ctx.on_cleanup(lambda x=rule["Id"]: _delete_resolver_rule(r53, x))
    second_domain = f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal."
    outcome = {}

    def do_replay():
        resp = r53.create_resolver_rule(
            CreatorRequestId=creator_request_id,
            Name=ctx.unique_name("sim2real-behav-rr-"),
            RuleType="SYSTEM",
            DomainName=second_domain,
        )
        outcome["id"] = resp["ResolverRule"]["Id"]
        return resp

    try:
        code, message = _client_error(do_replay)
    finally:
        # If the service allowed it, track the second rule for cleanup.
        if outcome.get("id"):
            ctx.on_cleanup(lambda x=outcome["id"]: _delete_resolver_rule(r53, x))
    assert code == "ResourceExistsException", (
        f"expected ResourceExistsException for replayed CreatorRequestId, got {code}"
    )
    expected_message = (
        f'[RSLVR-00701] Resolver rule with creator request ID "{creator_request_id}" already exists.'
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected replay must not have mutated the original rule --
    # an independent read at a different operation than the one that mutated.
    refetched = r53.get_resolver_rule(ResolverRuleId=rule["Id"])["ResolverRule"]
    assert refetched["DomainName"] == domain_name, (
        f"replayed CreatorRequestId was rejected but the original rule's DomainName "
        f"changed from {domain_name!r} to {refetched['DomainName']!r}"
    )

    # Positive control: a fresh, distinct CreatorRequestId is accepted normally, so the
    # rejection above is specific to the replayed id rather than the account/service
    # having gone globally unable to create resolver rules.
    other_request_id = ctx.unique_name("sim2real-behav-cr-idem-other-")
    other_domain = f"{ctx.unique_name('sim2real-behav-zone-')}.example.internal."
    other_rule = r53.create_resolver_rule(
        CreatorRequestId=other_request_id,
        Name=ctx.unique_name("sim2real-behav-rr-"),
        RuleType="SYSTEM",
        DomainName=other_domain,
    )["ResolverRule"]
    ctx.on_cleanup(lambda x=other_rule["Id"]: _delete_resolver_rule(r53, x))
    assert other_rule["Id"] != rule["Id"], (
        "a fresh CreatorRequestId minted the same rule Id as the original"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
