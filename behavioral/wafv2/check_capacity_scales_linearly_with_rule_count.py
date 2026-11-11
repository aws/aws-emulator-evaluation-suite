"""capacity-scales-linearly-with-rule-count."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "capacity-scales-linearly-with-rule-count"
GROUP = 'capacity'
SERVICES = ['wafv2']

# REGIONAL is usable from any endpoint/region; CLOUDFRONT scope requires us-east-1.
SCOPE = "REGIONAL"


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _expensive_rule(name, priority=0, n_transforms=5):
    """A ByteMatch rule with several non-NONE text transformations.

    Each non-NONE text transformation adds WCUs, so this is a cheap way to build
    rule sets whose aggregate capacity is far above the single-statement base cost.
    """
    transform_types = [
        "LOWERCASE",
        "URL_DECODE",
        "HTML_ENTITY_DECODE",
        "COMPRESS_WHITE_SPACE",
        "NORMALIZE_PATH",
        "CMD_LINE",
        "BASE64_DECODE",
        "CSS_DECODE",
    ][:n_transforms]
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": b"attack",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [
                    {"Priority": i, "Type": t} for i, t in enumerate(transform_types)
                ],
                "PositionalConstraint": "CONTAINS",
            }
        },
        "Action": {"Block": {}},
        "VisibilityConfig": _visibility_config(name),
    }


def _capacity(w, n: int) -> int:
    rules = [_expensive_rule(f"rule-{i}", priority=i, n_transforms=5) for i in range(n)]
    return w.check_capacity(Scope=SCOPE, Rules=rules)["Capacity"]


@tags("axis:happy-path", "cap:c7", "plane:control")
def run(ctx) -> None:
    """CheckCapacity is linear in rule count with a shared fixed cost: cost(10) == cost(1) + 9 *
    marginal, where 1 <= marginal < cost(1), and a repeated call returns the same value.
    """
    w = ctx.client("wafv2")
    one = _capacity(w, 1)
    two = _capacity(w, 2)
    marginal = two - one
    assert one >= 1, one
    assert marginal >= 1, f"marginal WCU per extra rule must be >=1, got {marginal}"

    # The transformation charge is shared across the whole rule set, not re-applied
    # per rule: a naive per-rule multiplicative model (or a stub keyed off len(Rules)
    # alone) would make the marginal cost of an extra identical rule equal the cost
    # of the first rule. Real WAF's marginal is strictly cheaper, because only the
    # first rule pays for the shared text-transformation set.
    assert marginal < one, (
        f"marginal cost per extra rule ({marginal}) must be strictly less than the "
        f"single-rule cost ({one}) -- a per-rule-multiplicative model or a "
        f"len(Rules)-keyed stub would make them equal"
    )

    ten = _capacity(w, 10)
    assert ten == one + 9 * marginal, f"expected {one + 9 * marginal}, got {ten}"

    # Pure computation: repeating the same request yields the same number.
    repeat = _capacity(w, 10)
    assert repeat == ten, f"CheckCapacity must be deterministic, got {repeat} then {ten}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
