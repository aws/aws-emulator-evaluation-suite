"""webacl-configuration-warning-on-inconsistent-override-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-configuration-warning-on-inconsistent-override-rejected"
GROUP = "error-semantics"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWebACL accepts a rule inspecting the request Body with no OversizeHandling (optional, default
    CONTINUE), and the web ACL reads back with that one rule and Body still empty.
    """
    wafv2 = ctx.client("wafv2")
    web_acl_name = ctx.unique_name("sim2real-behav-wacl-")
    created = wafv2.create_web_acl(
        Name=web_acl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": web_acl_name,
        },
        Rules=[
            {
                "Name": "inspect-body",
                "Priority": 0,
                "Action": {"Block": {}},
                "Statement": {
                    "ByteMatchStatement": {
                        "SearchString": b"malicious-payload",
                        "FieldToMatch": {"Body": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }
                },
                "VisibilityConfig": {
                    "SampledRequestsEnabled": False,
                    "CloudWatchMetricsEnabled": False,
                    "MetricName": "inspect-body",
                },
            }
        ],
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl(wafv2, web_acl_name, created["Id"]))

    found = wafv2.get_web_acl(Name=web_acl_name, Scope="REGIONAL", Id=created["Id"])["WebACL"]
    assert found["Name"] == web_acl_name, (
        f"expected persisted web ACL named {web_acl_name!r}, got {found['Name']!r}"
    )
    rules = found["Rules"]
    assert [r["Name"] for r in rules] == ["inspect-body"], f"expected the one Body rule, got {rules!r}"
    body = rules[0]["Statement"]["ByteMatchStatement"]["FieldToMatch"]["Body"]
    # The omitted setting reads back omitted, not as an explicit CONTINUE.
    assert body == {}, f"expected Body to read back exactly as sent, with no OversizeHandling, got {body!r}"


def _delete_web_acl(wafv2, name, web_acl_id):
    try:
        lock_token = wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=web_acl_id)["LockToken"]
        wafv2.delete_web_acl(Name=name, Scope="REGIONAL", Id=web_acl_id, LockToken=lock_token)
    except ClientError as err:
        if err.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

