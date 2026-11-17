"""create-rule-condition-wildcards-exceeding-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rule-condition-wildcards-exceeding-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]

_FIXED_RESPONSE = {
    "Type": "fixed-response",
    "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"},
}


def _teardown(undo, *not_found: str):
    """Run ``undo()``; a failed delete raises unless its code is one of ``not_found``."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _refused(fn):
    """The (code, message) ``fn`` is refused with. Raises, naming the result, on an unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the rule to be refused, but it was created: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRule refuses a path-pattern condition carrying seven '*'/'?' wildcard characters with
    the exact over-limit error, creating no rule, while six wildcards at the same priority are
    accepted and listed."""
    elbv2 = ctx.client("elbv2")
    net = ctx.network()
    subnets = net.subnet_ids[:2]
    assert len(subnets) == 2, f"the run's network has {len(subnets)} subnet(s), an ALB needs two"

    lb_name = ctx.unique_name("sim2real-wildlim-")[:32].rstrip("-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnets, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn), "LoadBalancerNotFound"))
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[_FIXED_RESPONSE],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_listener(ListenerArn=listener_arn), "ListenerNotFound"))

    over_limit_value = "/" + "*".join(f"w{i}" for i in range(8))  # eight segments, seven '*' wildcards
    code, message = _refused(lambda: elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=1,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": [over_limit_value]}}],
        Actions=[_FIXED_RESPONSE],
    ))
    assert code == "ValidationError", f"expected ValidationError for seven condition wildcards, got {code!r}"
    expected_message = "A rule can only have '6' condition wildcards"
    assert message == expected_message, f"MSG={message!r}"

    rules_at_priority_1 = [
        r for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"] if r["Priority"] == "1"
    ]
    assert rules_at_priority_1 == [], f"a rule exists at priority 1 after the refusal: {rules_at_priority_1!r}"

    in_limit_value = "/w0*w1*w2*w3*w4*w5"  # six '*' wildcard characters, the documented ceiling
    ok = elbv2.create_rule(
        ListenerArn=listener_arn,
        Priority=1,
        Conditions=[{"Field": "path-pattern", "PathPatternConfig": {"Values": [in_limit_value]}}],
        Actions=[_FIXED_RESPONSE],
    )["Rules"][0]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_rule(RuleArn=ok["RuleArn"]), "RuleNotFound"))
    echoed = ok["Conditions"][0]["PathPatternConfig"]["Values"]
    assert echoed == [in_limit_value], f"the six-wildcard rule echoed {echoed!r}, expected {[in_limit_value]!r}"

    rules_at_priority_1 = [
        r for r in elbv2.describe_rules(ListenerArn=listener_arn)["Rules"] if r["Priority"] == "1"
    ]
    assert [r["RuleArn"] for r in rules_at_priority_1] == [ok["RuleArn"]], (
        f"expected exactly the accepted rule at priority 1, got {rules_at_priority_1!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
