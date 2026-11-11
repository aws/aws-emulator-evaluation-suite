"""op-contract-delete-traffic-mirror-filter-rule."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-traffic-mirror-filter-rule"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTrafficMirrorFilterRule removes exactly the targeted rule (leaving sibling rules
    intact) and is confirmed gone; a bogus rule id is rejected with a rule-specific NotFound."""
    ec2 = ctx.client("ec2")
    _tag_spec = lambda resource_type: [  # noqa: E731
        {"ResourceType": resource_type, "Tags": [{"Key": "sim2real", "Value": "1"}]}
    ]

    filter_id = ec2.create_traffic_mirror_filter(
        TagSpecifications=_tag_spec("traffic-mirror-filter")
    )["TrafficMirrorFilter"]["TrafficMirrorFilterId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_filter(TrafficMirrorFilterId=filter_id))

    rule_a = ec2.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="ingress",
        RuleNumber=1,
        RuleAction="accept",
        DestinationCidrBlock="0.0.0.0/0",
        SourceCidrBlock="10.0.0.0/8",
        TagSpecifications=_tag_spec("traffic-mirror-filter-rule"),
    )["TrafficMirrorFilterRule"]["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_filter_rule(
        TrafficMirrorFilterRuleId=rule_a
    )))

    rule_b = ec2.create_traffic_mirror_filter_rule(
        TrafficMirrorFilterId=filter_id,
        TrafficDirection="egress",
        RuleNumber=1,
        RuleAction="accept",
        DestinationCidrBlock="0.0.0.0/0",
        SourceCidrBlock="0.0.0.0/0",
        TagSpecifications=_tag_spec("traffic-mirror-filter-rule"),
    )["TrafficMirrorFilterRule"]["TrafficMirrorFilterRuleId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_traffic_mirror_filter_rule(
        TrafficMirrorFilterRuleId=rule_b
    )))

    # Success path: deleting rule_a leaves rule_b intact.
    resp = ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rule_a)
    assert resp["TrafficMirrorFilterRuleId"] == rule_a, (
        f"expected DeleteTrafficMirrorFilterRule to echo the deleted rule id {rule_a!r}, "
        f"got {resp.get('TrafficMirrorFilterRuleId')!r}"
    )

    remaining = ec2.describe_traffic_mirror_filter_rules(
        TrafficMirrorFilterRuleIds=[rule_b]
    )["TrafficMirrorFilterRules"]
    assert len(remaining) == 1 and remaining[0]["TrafficMirrorFilterRuleId"] == rule_b, (
        f"expected sibling rule {rule_b!r} to survive deletion of {rule_a!r} untouched, "
        f"got {remaining!r}"
    )

    code, msg = _client_error(
        lambda: ec2.describe_traffic_mirror_filter_rules(TrafficMirrorFilterRuleIds=[rule_a])
    )
    assert code == "InvalidTrafficMirrorFilterRuleId.NotFound", f"expected a TrafficMirrorFilterRule NotFound code, got {code!r}"
    expected_msg = f"{rule_a} does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Deletion is not idempotent: a second delete of the same now-gone rule must also
    # be rejected with the specific NotFound code, not silently succeed.
    code, msg = _client_error(
        lambda: ec2.delete_traffic_mirror_filter_rule(TrafficMirrorFilterRuleId=rule_a)
    )
    assert code == "InvalidTrafficMirrorFilterRuleId.NotFound", f"expected a second delete of {rule_a!r} to return a TrafficMirrorFilterRule NotFound code, got {code!r}"
    expected_msg = f"{rule_a} does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Error boundary: deleting a rule id that never existed.
    code, msg = _client_error(
        lambda: ec2.delete_traffic_mirror_filter_rule(
            TrafficMirrorFilterRuleId="tmfr-00000000000000000"
        )
    )
    assert code == "InvalidTrafficMirrorFilterRuleId.NotFound", f"expected a TrafficMirrorFilterRule NotFound code, got {code!r}"
    expected_msg = "tmfr-00000000000000000 does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTrafficMirrorFilterRuleId.NotFound":
            raise


def _client_error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
