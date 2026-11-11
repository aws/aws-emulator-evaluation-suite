"""create-webacl-managed-rule-group-pinned-version-persisted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-webacl-managed-rule-group-pinned-version-persisted"
GROUP = "error-semantics"
SERVICES = ["wafv2"]

# AWS prunes fully-expired versions out of ListAvailableManagedRuleGroupVersions, but
# DescribeManagedRuleGroup still distinguishes "existed and expired"
# (WAFExpiredManagedRuleGroupVersionException) from "never existed"
# (WAFNonexistentItemException) for an old VersionName -- so probe read-only historical
# version identifiers for a confirmed-expired one instead of trusting the live list.
_CANDIDATE_VERSIONS = [
    ("AWS", "AWSManagedRulesCommonRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesCommonRuleSet", "Version_1.1"),
    ("AWS", "AWSManagedRulesCommonRuleSet", "Version_1.2"),
    ("AWS", "AWSManagedRulesSQLiRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesSQLiRuleSet", "Version_1.1"),
    ("AWS", "AWSManagedRulesKnownBadInputsRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesLinuxRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesWindowsRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesUnixRuleSet", "Version_1.0"),
    ("AWS", "AWSManagedRulesAnonymousIpList", "Version_1.0"),
    ("AWS", "AWSManagedRulesAmazonIpReputationList", "Version_1.0"),
]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWebACL persists an explicit, currently valid managed rule group Version (read back via
    GetWebACL) and rejects a pinned expired version with WAFExpiredManagedRuleGroupVersionException.
    """
    wafv2 = ctx.client("wafv2")

    versions = wafv2.list_available_managed_rule_group_versions(
        VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope="REGIONAL"
    )
    valid_version = versions.get("CurrentDefaultVersion") or (
        versions["Versions"][0]["Name"] if versions.get("Versions") else None
    )
    assert valid_version, "expected at least one available version for AWSManagedRulesCommonRuleSet"

    webacl_name = ctx.unique_name("sim2real-behav-webacl-")
    created = wafv2.create_web_acl(
        Name=webacl_name,
        Scope="REGIONAL",
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config(webacl_name),
        Rules=[_managed_rule_group_rule("common-rules", "AWS", "AWSManagedRulesCommonRuleSet", valid_version)],
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )["Summary"]
    webacl_id = created["Id"]
    ctx.on_cleanup(lambda: _best_effort_delete_webacl(wafv2, webacl_name, webacl_id))

    fetched = wafv2.get_web_acl(Name=webacl_name, Scope="REGIONAL", Id=webacl_id)
    rule_statement = fetched["WebACL"]["Rules"][0]["Statement"]["ManagedRuleGroupStatement"]
    assert rule_statement["VendorName"] == "AWS", (
        f"expected VendorName AWS, got {rule_statement.get('VendorName')!r}"
    )
    assert rule_statement["Name"] == "AWSManagedRulesCommonRuleSet", (
        f"expected Name AWSManagedRulesCommonRuleSet, got {rule_statement.get('Name')!r}"
    )
    assert rule_statement["Version"] == valid_version, (
        f"expected pinned Version {valid_version!r} to persist, got {rule_statement.get('Version')!r}"
    )

    # AWS-owned managed rule groups can be described without a Marketplace subscription.
    expired = _find_confirmed_expired_version(wafv2)
    if expired is None:
        raise AssertionError(
            "no confirmed-expired managed rule group version could be "
            "discovered among the sampled historical VersionNames (AWS "
            "prunes expired versions from the offered catalog, and which "
            "old VersionName still resolves to "
            "WAFExpiredManagedRuleGroupVersionException rotates over time); "
            "rerun later or widen _CANDIDATE_VERSIONS -- the pinned-version "
            "CreateWebACL above still ran and was asserted for real state"
        )
    vendor_name, rule_group_name, expired_version = expired

    expired_webacl_name = ctx.unique_name("sim2real-behav-expired-")
    try:
        leaked = wafv2.create_web_acl(
            Name=expired_webacl_name,
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig=_visibility_config(expired_webacl_name),
            Rules=[
                _managed_rule_group_rule(
                    "expired-rules", vendor_name, rule_group_name, expired_version
                )
            ],
            Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
    else:
        leaked_id = leaked["Summary"]["Id"]
        ctx.on_cleanup(lambda: _best_effort_delete_webacl(wafv2, expired_webacl_name, leaked_id))
        raise AssertionError(
            f"CreateWebACL unexpectedly succeeded pinning expired version "
            f"{expired_version!r} of {vendor_name}/{rule_group_name}"
        )
    assert code == "WAFExpiredManagedRuleGroupVersionException", (
        f"expected WAFExpiredManagedRuleGroupVersionException, got {code!r}"
    )
    assert message == (
        f"You're trying to use an expired version ({expired_version}) of {rule_group_name} "
        f"by {vendor_name}."
    ), message

    listed = wafv2.list_web_acls(Scope="REGIONAL").get("WebACLs", [])
    assert not any(w["Name"] == expired_webacl_name for w in listed), (
        "the rejected create must not have left a web ACL behind"
    )


def _visibility_config(metric_name: str) -> dict:
    return {
        "SampledRequestsEnabled": True,
        "CloudWatchMetricsEnabled": True,
        "MetricName": metric_name.replace(".", ""),
    }


def _managed_rule_group_rule(name: str, vendor_name: str, rule_group_name: str, version: str) -> dict:
    return {
        "Name": name,
        "Priority": 0,
        "OverrideAction": {"None": {}},
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": vendor_name,
                "Name": rule_group_name,
                "Version": version,
            }
        },
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", ""),
        },
    }


def _find_confirmed_expired_version(wafv2):
    for vendor, group_name, version in _CANDIDATE_VERSIONS:
        try:
            wafv2.describe_managed_rule_group(
                VendorName=vendor, Name=group_name, Scope="REGIONAL", VersionName=version
            )
        except ClientError as err:
            if err.response["Error"]["Code"] == "WAFExpiredManagedRuleGroupVersionException":
                return vendor, group_name, version
    return None


def _best_effort_delete_webacl(wafv2, name: str, webacl_id: str) -> None:
    try:
        current = wafv2.get_web_acl(Name=name, Scope="REGIONAL", Id=webacl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise
        return
    try:
        wafv2.delete_web_acl(
            Name=name, Scope="REGIONAL", Id=webacl_id, LockToken=current["LockToken"]
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
