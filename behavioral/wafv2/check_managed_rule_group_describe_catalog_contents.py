"""managed-rule-group-describe-catalog-contents."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "managed-rule-group-describe-catalog-contents"
GROUP = 'managed-rule-groups'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)


def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    retryable = codes or _TRANSIENT_CODES
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in retryable:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc


def _list_all(list_fn, key, scope=SCOPE):
    """Fully paginate one of the WAFv2 List* operations (marker-paginated, 100/page)."""
    items = []
    marker = None
    while True:
        kwargs = {"Scope": scope, "Limit": 100}
        if marker:
            kwargs["NextMarker"] = marker
        resp = list_fn(**kwargs)
        page = resp.get(key, [])
        items.extend(page)
        marker = resp.get("NextMarker")
        if not marker or not page:
            break
    return items


def _label_namespaces(names):
    """The set of four-segment label namespaces ('awswaf:managed:<vendor>:<group>:') in names.

    DescribeManagedRuleGroup does not return the modeled LabelNamespace field for AWS-vendor
    groups, so the namespace is read off the labels themselves; a well-formed managed group
    publishes all of its own labels under exactly one.
    """
    return {":".join(n.split(":")[:4]) + ":" for n in names}

# AWS-vendor managed rule groups listed by ListAvailableManagedRuleGroups.
_EXPECTED_AWS_GROUPS = {
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesAdminProtectionRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesLinuxRuleSet",
    "AWSManagedRulesUnixRuleSet",
    "AWSManagedRulesWindowsRuleSet",
    "AWSManagedRulesPHPRuleSet",
    "AWSManagedRulesWordPressRuleSet",
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesAnonymousIpList",
    "AWSManagedRulesBotControlRuleSet",
    "AWSManagedRulesATPRuleSet",
    "AWSManagedRulesACFPRuleSet",
}

# Versioning support is itself catalog data: the IP-list groups are unversioned.
_UNVERSIONED = {"AWSManagedRulesAmazonIpReputationList", "AWSManagedRulesAnonymousIpList"}

# The documented capacity of the core rule set.
_CRS_CAPACITY = 700
_CRS_RULES = {"NoUserAgent_HEADER", "SizeRestrictions_BODY"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeManagedRuleGroup returns real per-group catalog data (rules, labels, capacity,
    versions) for AWS managed groups, distinct per group, rather than a generic placeholder.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html
    """
    w = ctx.client("wafv2")

    groups = _list_all(w.list_available_managed_rule_groups, "ManagedRuleGroups")
    aws_groups = {g["Name"]: g for g in groups if g.get("VendorName") == "AWS"}
    missing = _EXPECTED_AWS_GROUPS - set(aws_groups)
    assert not missing, f"AWS managed rule group catalog is missing {sorted(missing)}"
    for name in _UNVERSIONED:
        assert aws_groups[name].get("VersioningSupported") is False, (
            f"{name} is an unversioned managed rule group; "
            f"VersioningSupported={aws_groups[name].get('VersioningSupported')!r}"
        )
    assert aws_groups["AWSManagedRulesCommonRuleSet"].get("VersioningSupported") is True, \
        aws_groups["AWSManagedRulesCommonRuleSet"]
    for name, g in aws_groups.items():
        assert g.get("Description"), f"{name} has no catalog Description"

    crs = _retry_transient(lambda: w.describe_managed_rule_group(
        VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope=SCOPE
    ))
    assert crs["Capacity"] == _CRS_CAPACITY, (
        f"AWSManagedRulesCommonRuleSet capacity is {_CRS_CAPACITY} WCU, "
        f"got {crs['Capacity']}"
    )
    rule_names = {r["Name"] for r in crs.get("Rules", [])}
    assert len(rule_names) >= 10, (
        f"the core rule set contains many rules; DescribeManagedRuleGroup returned "
        f"{len(rule_names)}: {sorted(rule_names)}"
    )
    assert _CRS_RULES <= rule_names, (
        f"the core rule set must contain {sorted(_CRS_RULES)}; got {sorted(rule_names)}"
    )
    for r in crs["Rules"]:
        assert r.get("Action"), f"managed rule {r['Name']} reports no Action: {r}"

    labels = [lbl["Name"] for lbl in crs.get("AvailableLabels", [])]
    assert labels, "the core rule set publishes AvailableLabels; got none"
    bad_ns = [n for n in labels if not n.startswith("awswaf:managed:aws:")]
    assert not bad_ns, (
        f"AWS managed rule group labels live under the reserved "
        f"'awswaf:managed:aws:' namespace; got {bad_ns[:5]}"
    )
    # AWS omits the modeled LabelNamespace field for AWS-vendor groups; the namespace is
    # read off the labels instead.
    assert "LabelNamespace" not in crs, (
        f"DescribeManagedRuleGroup does not report LabelNamespace for an AWS-vendor group; the "
        f"namespace is derivable from AvailableLabels. Got {crs.get('LabelNamespace')!r}"
    )
    assert _label_namespaces(labels) == {"awswaf:managed:aws:core-rule-set:"}, (
        f"every core rule set label lives under the single namespace "
        f"'awswaf:managed:aws:core-rule-set:'; got {sorted(_label_namespaces(labels))}"
    )
    # The namespace slug ('core-rule-set') is not derivable from the group name.
    assert "AWSManagedRulesCommonRuleSet" not in "".join(labels), (
        f"the label namespace uses the group's published slug, not its API name: {labels[:3]}"
    )
    # The AWS-owned managed-rule update topic is in us-east-1 regardless of the caller's region.
    sns = crs["SnsTopicArn"]
    sns_parts = sns.split(":")
    assert sns_parts[:4] == ["arn", "aws", "sns", "us-east-1"], (
        f"the managed-rule notification topic is a us-east-1 SNS ARN, got {sns!r}"
    )
    assert sns_parts[5] == "aws-managed-waf-rule-notifications", sns

    # The core rule set consumes no labels and omits the key (not an empty list), so the
    # ConsumedLabels contract is asserted on Bot Control, whose rules read its own labels.
    assert "ConsumedLabels" not in crs, (
        f"the core rule set consumes no labels and must omit the key entirely, got "
        f"{crs.get('ConsumedLabels')!r}"
    )
    botc = _retry_transient(lambda: w.describe_managed_rule_group(
        VendorName="AWS", Name="AWSManagedRulesBotControlRuleSet", Scope=SCOPE
    ))
    consumed = [lbl["Name"] for lbl in botc["ConsumedLabels"]]
    assert consumed, "AWSManagedRulesBotControlRuleSet consumes labels; got none"
    assert _label_namespaces(consumed) == {"awswaf:managed:aws:bot-control:"}, (
        f"Bot Control consumes only its own namespace's labels, got "
        f"{sorted(_label_namespaces(consumed))}"
    )
    botc_labels = [lbl["Name"] for lbl in botc["AvailableLabels"]]
    assert set(consumed) <= set(botc_labels), (
        f"every consumed label must also be published by the group: "
        f"{sorted(set(consumed) - set(botc_labels))[:5]}"
    )
    # Bot Control also publishes the vendor-independent token/captcha namespaces, so its
    # published labels span more than one namespace.
    assert "awswaf:managed:token:absent:" in _label_namespaces(botc_labels), (
        f"Bot Control publishes the token-status labels too, got "
        f"{sorted(_label_namespaces(botc_labels))}"
    )

    sqli = _retry_transient(lambda: w.describe_managed_rule_group(
        VendorName="AWS", Name="AWSManagedRulesSQLiRuleSet", Scope=SCOPE
    ))
    sqli_rules = {r["Name"] for r in sqli.get("Rules", [])}
    assert sqli_rules, "AWSManagedRulesSQLiRuleSet returned no Rules"
    assert sqli_rules != rule_names, (
        "SQLiRuleSet and CommonRuleSet returned identical rule sets -- "
        "the catalog is not per-group"
    )
    assert sqli["Capacity"] != crs["Capacity"], (
        f"SQLiRuleSet and CommonRuleSet both report capacity {sqli['Capacity']}"
    )
    sqli_labels = [lbl["Name"] for lbl in sqli.get("AvailableLabels", [])]
    assert _label_namespaces(sqli_labels) == {"awswaf:managed:aws:sql-database:"}, (
        f"AWSManagedRulesSQLiRuleSet publishes its labels under "
        f"'awswaf:managed:aws:sql-database:'; got {sorted(_label_namespaces(sqli_labels))}"
    )
    assert _label_namespaces(sqli_labels) != _label_namespaces(labels), (
        "SQLiRuleSet and CommonRuleSet share a label namespace -- the catalog is not per-group"
    )

    versions = _retry_transient(lambda: w.list_available_managed_rule_group_versions(
        VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope=SCOPE, Limit=50
    ))
    default = versions["CurrentDefaultVersion"]
    listed = [v["Name"] for v in versions.get("Versions", [])]
    assert listed, "AWSManagedRulesCommonRuleSet is versioned but listed no versions"
    assert default in listed, (
        f"CurrentDefaultVersion {default!r} is not among the listed versions {listed}"
    )
    assert default.startswith("Version_"), default
    pinned = _retry_transient(lambda: w.describe_managed_rule_group(
        VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope=SCOPE,
        VersionName=default,
    ))
    assert pinned["Capacity"] == crs["Capacity"], (
        f"describing the group at its own default version {default} changed capacity: "
        f"{pinned['Capacity']} vs {crs['Capacity']}"
    )
    assert {r["Name"] for r in pinned.get("Rules", [])} == rule_names, (
        "describing the group at its own default version changed the rule set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
