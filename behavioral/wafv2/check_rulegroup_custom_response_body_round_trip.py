"""rulegroup-custom-response-body-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rulegroup-custom-response-body-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRuleGroup returns a TEXT_PLAIN CustomResponseBody with quotes, angle brackets, an ampersand and
    multi-byte text byte-for-byte, with the rule's Block action keeping key body1 and ResponseCode 403.
    """
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-rg-crb-")
    scope = "REGIONAL"
    vis = {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": name}

    body_content = "blocked \"quoted\" <tag> & special \u00a9 \u4e2d\u6587 \U0001F525 text"
    custom_response_bodies = {
        "body1": {"ContentType": "TEXT_PLAIN", "Content": body_content}
    }

    rule = {
        "Name": "block-rule",
        "Priority": 1,
        "Statement": {"GeoMatchStatement": {"CountryCodes": ["CN"]}},
        "Action": {
            "Block": {
                "CustomResponse": {"ResponseCode": 403, "CustomResponseBodyKey": "body1"}
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": "block-rule",
        },
    }

    created = wafv2.create_rule_group(
        Name=name,
        Scope=scope,
        Capacity=10,
        Rules=[rule],
        VisibilityConfig=vis,
        CustomResponseBodies=custom_response_bodies,
    )
    summary = created["Summary"]
    rg_id = summary["Id"]

    def _cleanup():
        try:
            cur = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
            wafv2.delete_rule_group(Name=name, Scope=scope, Id=rg_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    got = wafv2.get_rule_group(Name=name, Scope=scope, Id=rg_id)
    returned_bodies = got["RuleGroup"]["CustomResponseBodies"]
    assert "body1" in returned_bodies, (
        f"CustomResponseBodies key 'body1' missing on GetRuleGroup: {sorted(returned_bodies)}"
    )
    assert returned_bodies["body1"]["ContentType"] == "TEXT_PLAIN", (
        f"ContentType mutated on round trip: {returned_bodies['body1']['ContentType']!r}"
    )
    assert returned_bodies["body1"]["Content"] == body_content, (
        f"CustomResponseBody Content mutated on round trip: {returned_bodies['body1']['Content']!r}"
    )

    returned_rule = got["RuleGroup"]["Rules"][0]
    returned_custom_response = returned_rule["Action"]["Block"]["CustomResponse"]
    assert returned_custom_response["CustomResponseBodyKey"] == "body1", (
        f"CustomResponseBodyKey mutated on round trip: {returned_custom_response['CustomResponseBodyKey']!r}"
    )
    assert returned_custom_response["ResponseCode"] == 403, (
        f"ResponseCode mutated on round trip: {returned_custom_response['ResponseCode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
