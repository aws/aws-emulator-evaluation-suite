"""managed-rule-group-default-version-selection."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "managed-rule-group-default-version-selection"
GROUP = "server-side"
SERVICES = ["wafv2"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A web ACL referencing a managed rule group without Version stores no pinned Version on GetWebACL
    (it follows the vendor default), and the group's CurrentDefaultVersion is one of its listed
    available versions.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"
    vendor_name = "AWS"
    rule_group_name = "AWSManagedRulesCommonRuleSet"

    versions = wafv2.list_available_managed_rule_group_versions(
        VendorName=vendor_name, Name=rule_group_name, Scope=scope
    )
    default_version = versions.get("CurrentDefaultVersion")
    assert default_version, "expected a CurrentDefaultVersion for AWSManagedRulesCommonRuleSet"
    available_names = {v["Name"] for v in versions.get("Versions", [])}
    assert default_version in available_names, (
        "CurrentDefaultVersion must itself be one of the listed available versions"
    )

    name = ctx.unique_name("sim2real-behav-mrg-")
    metric_name = name.replace("-", "")
    create = wafv2.create_web_acl(
        Name=name,
        Scope=scope,
        DefaultAction={"Allow": {}},
        Rules=[
            {
                "Name": "managed-common-rule-set",
                "Priority": 0,
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": vendor_name,
                        "Name": rule_group_name,
                        # Version intentionally omitted -> should float to default.
                    }
                },
                "OverrideAction": {"None": {}},
                "VisibilityConfig": {
                    "SampledRequestsEnabled": True,
                    "CloudWatchMetricsEnabled": True,
                    "MetricName": f"{metric_name}rule",
                },
            }
        ],
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name,
        },
    )
    web_acl_id = create["Summary"]["Id"]
    ctx.on_cleanup(
        lambda: wafv2.delete_web_acl(
            Name=name,
            Scope=scope,
            Id=web_acl_id,
            LockToken=wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)["LockToken"],
        )
    )

    got = wafv2.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
    rules = got["WebACL"]["Rules"]
    assert len(rules) == 1, f"expected 1 rule on the web ACL, got {len(rules)}"
    statement = rules[0]["Statement"]["ManagedRuleGroupStatement"]
    assert statement["VendorName"] == vendor_name, (
        f"expected VendorName {vendor_name!r}, got {statement.get('VendorName')!r}"
    )
    assert statement["Name"] == rule_group_name, (
        f"expected Name {rule_group_name!r}, got {statement.get('Name')!r}"
    )
    # The statement we get back must NOT have been rewritten with a resolved version
    # string -- it must still show that no explicit Version was pinned, proving the
    # default-version resolution happens at evaluation time, not at storage time.
    assert "Version" not in statement or statement.get("Version") is None, (
        f"expected no pinned Version in the stored statement, got {statement.get('Version')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
