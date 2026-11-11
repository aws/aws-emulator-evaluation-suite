"""webacl-create-expired-managed-rule-group-version-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-create-expired-managed-rule-group-version-rejected"
GROUP = "error-semantics"
SERVICES = ["wafv2"]

# Historical version identifiers for long-lived AWS Managed Rules groups. AWS
# prunes fully-expired versions out of ListAvailableManagedRuleGroupVersions,
# but DescribeManagedRuleGroup still distinguishes "existed and expired" from
# "never existed" via WAFExpiredManagedRuleGroupVersionException vs
# WAFNonexistentItemException, so an expired one is found read-only before
# CreateWebACL is called.
_CANDIDATES = [
    ("AWS", "AWSManagedRulesCommonRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesCommonRuleSet", "Version_1.1"),
    ("AWS", "AWSManagedRulesCommonRuleSet", "Version_1.2"),
    ("AWS", "AWSManagedRulesSQLiRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesSQLiRuleSet", "Version_1.1"),
    ("AWS", "AWSManagedRulesLinuxRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesWindowsRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesUnixRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesAnonymousIpList", "Version_1.0"),
    ("AWS", "AWSManagedRulesAmazonIpReputationList", "Version_1.0"),
]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWebACL pinning an expired managed rule group version fails with
    WAFExpiredManagedRuleGroupVersionException and the exact message and lists no web ACL; the same rule
    without a pinned version is created and returned by GetWebACL.
    """
    wafv2 = ctx.client("wafv2")
    scope = "REGIONAL"

    expired = None
    for vendor, name, version in _CANDIDATES:
        try:
            wafv2.describe_managed_rule_group(
                VendorName=vendor, Name=name, Scope=scope, VersionName=version
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "WAFExpiredManagedRuleGroupVersionException":
                expired = (vendor, name, version)
                break
    if expired is None:
        raise AssertionError(
            "no confirmed-expired managed rule group version could be discovered among "
            "known historical AWS Managed Rules VersionNames (AWS prunes expired versions "
            "from the offered catalog); deliberately producing a fresh expired version "
            "requires vendor-only access via PutManagedRuleSetVersions/"
            "UpdateManagedRuleSetVersionExpiryDate, which a standard test account does not have"
        )
    vendor, name, version = expired

    web_acl_name = ctx.unique_name("sim2real-behav-webacl-")

    def _rule(version_name):
        stmt = {"VendorName": vendor, "Name": name}
        if version_name is not None:
            stmt["Version"] = version_name
        return {
            "Name": "managed-rule",
            "Priority": 0,
            "OverrideAction": {"None": {}},
            "Statement": {"ManagedRuleGroupStatement": stmt},
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": "managed-rule",
            },
        }

    def _create(version_name):
        return wafv2.create_web_acl(
            Name=web_acl_name,
            Scope=scope,
            DefaultAction={"Allow": {}},
            Rules=[_rule(version_name)],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName": web_acl_name,
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    try:
        _create(version)
        raise AssertionError(
            "CreateWebACL unexpectedly succeeded with a confirmed-expired managed rule group version"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "WAFExpiredManagedRuleGroupVersionException", (
            f"expected WAFExpiredManagedRuleGroupVersionException, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == (
            f"You're trying to use an expired version ({version}) of {name} by {vendor}."
        ), message

    names = [w["Name"] for w in wafv2.list_web_acls(Scope=scope).get("WebACLs", [])]
    assert web_acl_name not in names, (
        f"rejected CreateWebACL left {web_acl_name} visible in ListWebACLs"
    )

    # positive control: same rule shape without an explicit (expired) version succeeds
    created = _create(None)["Summary"]
    web_acl_id = created["Id"]

    def _cleanup():
        current = wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)
        wafv2.delete_web_acl(
            Name=web_acl_name, Scope=scope, Id=web_acl_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)

    # terminal: independent read (GetWebACL, a different operation than CreateWebACL)
    # confirms the vendor-default-version rule was actually persisted and is visible
    # at the destination, not just echoed back by the mutating call
    fetched = wafv2.get_web_acl(Name=web_acl_name, Scope=scope, Id=web_acl_id)["WebACL"]
    assert fetched["Name"] == web_acl_name, (
        f"expected GetWebACL to return {web_acl_name}, got {fetched['Name']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
