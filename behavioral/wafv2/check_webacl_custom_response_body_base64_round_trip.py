"""webacl-custom-response-body-base64-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "webacl-custom-response-body-base64-round-trip"
GROUP = "representation"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64-encoded custom response body on a WebACL Block rule is returned
    byte-for-byte unchanged by GetWebACL, both right after CreateWebACL and again
    after an UpdateWebACL that changes an unrelated field (Description)."""
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    name = ctx.unique_name("sim2real-behav-webacl-crb-")
    body_key = "customBody1"
    blob = base64.b64encode(os.urandom(48)).decode("ascii")

    rule = _block_rule_with_body("blockRule", 0, "blockme", body_key, "crbrulemetric")

    created = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("crbaclmetric"),
        Rules=[rule],
        CustomResponseBodies={body_key: {"ContentType": "TEXT_PLAIN", "Content": blob}},
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    web_acl_id = created["Summary"]["Id"]
    ctx.on_cleanup(lambda: wafv2.delete_web_acl(
        Name=name, Scope=scope, Id=web_acl_id,
        LockToken=wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"],
    ))

    got = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
    body1 = got["WebACL"]["CustomResponseBodies"][body_key]
    assert body1["Content"] == blob, f"expected Content {blob!r}, got {body1['Content']!r}"
    assert body1["ContentType"] == "TEXT_PLAIN", (
        f"expected ContentType TEXT_PLAIN, got {body1['ContentType']!r}"
    )

    lock_token = got["LockToken"]
    wafv2.update_web_acl(
        Name=name,
        Scope=scope,
        Id=web_acl_id,
        DefaultAction={"Allow": {}},
        Description="updated-description-unrelated-to-body",
        VisibilityConfig=_visibility_config("crbaclmetric"),
        Rules=[rule],
        CustomResponseBodies={body_key: {"ContentType": "TEXT_PLAIN", "Content": blob}},
        LockToken=lock_token,
    )

    got2 = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
    body2 = got2["WebACL"]["CustomResponseBodies"][body_key]
    assert body2["Content"] == blob, (
        f"Content mutated by an update to an unrelated field: expected {blob!r}, got {body2['Content']!r}"
    )
    assert got2["WebACL"]["Description"] == "updated-description-unrelated-to-body", (
        f"expected Description to reflect the update, got {got2['WebACL']['Description']!r}"
    )


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name,
    }


def _block_rule_with_body(name: str, priority: int, search_string: str, body_key: str, metric_name: str) -> dict:
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": search_string.encode("ascii"),
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        },
        "Action": {"Block": {"CustomResponse": {"ResponseCode": 403, "CustomResponseBodyKey": body_key}}},
        "VisibilityConfig": _visibility_config(metric_name),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
