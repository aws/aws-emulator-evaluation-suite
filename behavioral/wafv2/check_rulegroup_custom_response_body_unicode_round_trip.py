"""rulegroup-custom-response-body-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rulegroup-custom-response-body-unicode-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]

CUSTOM_BODY_KEY = "custom-error-body"
CUSTOM_CONTENT = (
    '{"message": "\u81ea\u5b9a\u4e49\u54cd\u5e94 blocked \U0001F600", '
    '"detail": "quoted \\"value\\" and a literal\\nnewline", '
    '"symbol": "\u2603"}'
)



@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A custom response body containing unicode letters, an emoji, an escaped
    quote, and a literal newline set on a RuleGroup survives CreateRuleGroup and
    is returned unchanged by GetRuleGroup."""
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-rulegroup-uni-")
    created = wafv2.create_rule_group(
        Name=name,
        Scope="REGIONAL",
        Capacity=10,
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name,
        },
        CustomResponseBodies={
            CUSTOM_BODY_KEY: {"ContentType": "APPLICATION_JSON", "Content": CUSTOM_CONTENT}
        },
    )["Summary"]
    rule_group_id = created["Id"]

    def _cleanup():
        current = wafv2.get_rule_group(Name=name, Scope="REGIONAL", Id=rule_group_id)
        wafv2.delete_rule_group(
            Name=name, Scope="REGIONAL", Id=rule_group_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)

    got = wafv2.get_rule_group(Name=name, Scope="REGIONAL", Id=rule_group_id)["RuleGroup"]
    bodies = got["CustomResponseBodies"]
    assert CUSTOM_BODY_KEY in bodies, bodies
    assert bodies[CUSTOM_BODY_KEY]["Content"] == CUSTOM_CONTENT, bodies[CUSTOM_BODY_KEY]["Content"]
    assert bodies[CUSTOM_BODY_KEY]["ContentType"] == "APPLICATION_JSON", bodies[CUSTOM_BODY_KEY][
        "ContentType"
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
