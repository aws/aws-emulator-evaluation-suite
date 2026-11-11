"""create-rule-condition-value-and-action-limits-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-rule-condition-value-and-action-limits-rejected"
GROUP = "negative-classes"
SERVICES = ["elbv2"]

_FIXED = {"Type": "fixed-response",
          "FixedResponseConfig": {"StatusCode": "200", "ContentType": "text/plain", "MessageBody": "ok"}}
_VALUES_MSG = "A rule can only have '5' condition values and regex values"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """The (code, message) ``fn`` is refused with. An unexpected success raises, naming it."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the rule to be refused, but it was created: {result!r}")


def _delete_lb_and_wait(elbv2, lb_arn: str, budget_s: float = 300.0) -> None:
    """DeleteLoadBalancer, then poll until the ARN no longer resolves; raises if it outlives the budget."""
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
    deadline = time.monotonic() + budget_s
    while True:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"the load balancer still resolves {budget_s}s after its delete")
        time.sleep(5)


def _rule_priorities(elbv2, listener_arn: str) -> list:
    rules = []
    for page in elbv2.get_paginator("describe_rules").paginate(ListenerArn=listener_arn):
        rules.extend(page["Rules"])
    return sorted(r["Priority"] for r in rules)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRule refuses six condition values (in one path-pattern, split over two conditions, or as Values), six
    conditions and two fixed-response actions with the exact error, creating no rule, while five values at a
    neighbouring priority are accepted and listed."""
    elbv2 = ctx.client("elbv2")
    net = ctx.network()
    subnets = net.subnet_ids[:2]
    assert len(subnets) == 2, f"the run's network has {len(net.subnet_ids)} subnet(s), an ALB needs two"

    lb_name = ctx.unique_name("sim2real-rulelim-")[:32].rstrip("-")
    lb_arn = elbv2.create_load_balancer(
        Name=lb_name, Subnets=subnets, Scheme="internal", Type="application",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_lb_and_wait(elbv2, lb_arn))
    listener_arn = elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80, DefaultActions=[_FIXED],
    )["Listeners"][0]["ListenerArn"]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_listener(ListenerArn=listener_arn), "ListenerNotFound"))

    def path(values):
        return {"Field": "path-pattern", "PathPatternConfig": {"Values": values}}

    def host(values):
        return {"Field": "host-header", "HostHeaderConfig": {"Values": values}}

    refusals = [
        (11, [path([f"/p{i}" for i in range(6)])], [_FIXED], "ValidationError", _VALUES_MSG),
        (12, [host(["a.example.com", "b.example.com", "c.example.com"]), path(["/x", "/y", "/z"])], [_FIXED],
         "ValidationError", _VALUES_MSG),
        (13, [{"Field": "path-pattern", "Values": [f"/l{i}" for i in range(6)]}], [_FIXED],
         "ValidationError", _VALUES_MSG),
        (14, [path(["/a"]), host(["h.example.com"]),
              {"Field": "http-request-method", "HttpRequestMethodConfig": {"Values": ["GET"]}},
              {"Field": "source-ip", "SourceIpConfig": {"Values": ["10.0.0.0/8"]}},
              {"Field": "query-string", "QueryStringConfig": {"Values": [{"Key": "k", "Value": "v"}]}},
              {"Field": "http-header", "HttpHeaderConfig": {"HttpHeaderName": "X-A", "Values": ["1"]}}],
         [_FIXED], "ValidationError", "You can specify up to 5 conditions"),
        (15, [path(["/q"])], [dict(_FIXED, Order=1), dict(_FIXED, Order=2)],
         "InvalidLoadBalancerAction", "You cannot specify multiple of the following action type: 'fixed-response'"),
    ]
    for priority, conditions, actions, want_code, want_msg in refusals:
        def create(priority=priority, conditions=conditions, actions=actions):
            return elbv2.create_rule(ListenerArn=listener_arn, Priority=priority, Conditions=conditions, Actions=actions)

        try:
            created = create()
        except ClientError as exc:
            code, msg = exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        else:
            arn = created["Rules"][0]["RuleArn"]
            ctx.on_cleanup(_teardown(lambda arn=arn: elbv2.delete_rule(RuleArn=arn), "RuleNotFound"))
            raise AssertionError(f"priority {priority}: the over-limit rule was created")
        assert code == want_code, f"priority {priority}: expected {want_code}, got {code!r}"
        assert msg == want_msg, f"priority {priority}: expected message {want_msg!r}, got {msg!r}"

    # Positive control: five values, the documented ceiling, at a neighbouring priority.
    ok = elbv2.create_rule(
        ListenerArn=listener_arn, Priority=20, Conditions=[path([f"/p{i}" for i in range(5)])], Actions=[_FIXED],
    )["Rules"][0]
    ctx.on_cleanup(_teardown(lambda: elbv2.delete_rule(RuleArn=ok["RuleArn"]), "RuleNotFound"))
    echoed = ok["Conditions"][0]["PathPatternConfig"]["Values"]
    assert echoed == [f"/p{i}" for i in range(5)], f"the five-value rule echoed {echoed!r}"

    priorities = _rule_priorities(elbv2, listener_arn)
    assert priorities == ["20", "default"], (
        f"the listener lists rules at {priorities!r}; only the accepted rule and the default may exist"
    )

    # Release the load balancer inside the check's own budget, so the run's network is free to go.
    elbv2.delete_rule(RuleArn=ok["RuleArn"])
    elbv2.delete_listener(ListenerArn=listener_arn)
    _delete_lb_and_wait(elbv2, lb_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
