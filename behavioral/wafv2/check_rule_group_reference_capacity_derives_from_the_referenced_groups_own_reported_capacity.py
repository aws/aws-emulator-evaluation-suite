"""rule-group-reference-capacity-derives-from-the-referenced-groups-own-reported-capacity."""
from __future__ import annotations

import random
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-group-reference-capacity-derives-from-the-referenced-groups-own-reported-capacity"
GROUP = "capacity"
SERVICES = ["wafv2"]

SCOPE = "REGIONAL"
ERR_NONEXISTENT = "WAFNonexistentItemException"

_TRANSIENT = frozenset({"ThrottlingException", "WAFInternalErrorException",
                        "WAFOptimisticLockException", "WAFUnavailableEntityException"})


def _tok(n=10):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _vis(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _retry_transient(fn, *, timeout_s=240.0, interval_s=10.0):
    """Bounded retry over WAF's eventually-consistent control-plane codes only.

    Every other ClientError is re-raised so a real refusal is never turned into a timeout.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") not in _TRANSIENT:
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _list_all(list_fn, key):
    """Fully paginate one of the WAFv2 List* operations (marker-paginated, 100/page)."""
    items = []
    marker = None
    while True:
        kwargs = {"Scope": SCOPE, "Limit": 100}
        if marker:
            kwargs["NextMarker"] = marker
        resp = list_fn(**kwargs)
        page = resp.get(key, [])
        items.extend(page)
        marker = resp.get("NextMarker")
        if not marker or not page:
            break
    return items


def _delete_locked(getter, deleter, name, id_, label):
    """Delete a WAFv2 entity, refetching its LockToken; raise if it cannot be deleted in time.

    An already-absent entity counts as deleted.
    """
    deadline = time.monotonic() + 240.0
    while True:
        try:
            token = getter(Name=name, Scope=SCOPE, Id=id_)["LockToken"]
            deleter(Name=name, Scope=SCOPE, Id=id_, LockToken=token)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == ERR_NONEXISTENT:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"wafv2 {label} {name} ({id_}) not deleted: {code}"
                ) from exc
            time.sleep(5.0)


@tags("axis:happy-path", "concern:representation", "plane:control", "cap:c1")
def run(ctx) -> None:
    """A rule-group reference's WCU cost tracks the referenced group's own capacity (declared or
    used), a managed reference costs DescribeManagedRuleGroup's Capacity, and GetWebACL's Capacity
    equals the additive CheckCapacity sum. No WCU number or managed version is pinned.

    Reference: https://docs.aws.amazon.com/waf/latest/developerguide/aws-waf-capacity-units.html
    """
    w = ctx.client("wafv2")

    # ---- an own rule group, twice: identical rules, DIFFERENT declared capacity.
    inner = {"Name": "inner", "Priority": 0,
             "Statement": {"XssMatchStatement": {
                 "FieldToMatch": {"QueryString": {}},
                 "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}},
             "Action": {"Count": {}}, "VisibilityConfig": _vis("inner")}
    used = _retry_transient(lambda: w.check_capacity(Scope=SCOPE, Rules=[inner]))["Capacity"]
    assert used > 0, f"CheckCapacity priced the rule group's only rule at {used} WCU"

    headroom = 500
    groups = {}
    for label, declared in (("tight", used), ("loose", used + headroom)):
        name = "sim2realbehavwafrg" + _tok(10)
        summary = _retry_transient(lambda: w.create_rule_group(
            Name=name, Scope=SCOPE, Capacity=declared, Rules=[inner],
            VisibilityConfig=_vis(name[:100]),
            Tags=[{"Key": "sim2real", "Value": CHECK},
                  {"Key": "sim2real:managed", "Value": "true"}],
        ))["Summary"]
        ctx.on_cleanup(lambda n=name, i=summary["Id"]: _delete_locked(
            w.get_rule_group, w.delete_rule_group, n, i, "RuleGroup"))
        got = w.get_rule_group(Name=name, Scope=SCOPE, Id=summary["Id"])["RuleGroup"]
        assert got["Capacity"] == declared, (
            f"the rule group did not report back the immutable Capacity it was created with: "
            f"reported={got['Capacity']!r}, requested={declared!r}"
        )
        groups[label] = {"name": name, "arn": summary["ARN"], "declared": declared}

    def _ref_rule(arn, name="groupref", priority=0):
        return {"Name": name, "Priority": priority,
                "Statement": {"RuleGroupReferenceStatement": {"ARN": arn}},
                "OverrideAction": {"None": {}}, "VisibilityConfig": _vis(name)}

    tight_cost = _retry_transient(lambda: w.check_capacity(
        Scope=SCOPE, Rules=[_ref_rule(groups["tight"]["arn"])]))["Capacity"]
    loose_cost = _retry_transient(lambda: w.check_capacity(
        Scope=SCOPE, Rules=[_ref_rule(groups["loose"]["arn"])]))["Capacity"]

    # A reference is never free and never cheaper than the rules it pulls in.
    assert tight_cost >= used, (
        f"a reference to a rule group whose rules cost {used} WCU was priced at {tight_cost} WCU, "
        f"which is less than the rules themselves"
    )
    # The docs do not say whether a reference is priced from DECLARED capacity (groups differ by
    # the headroom) or USED capacity (identical); exactly one reading must hold.
    tracks_declared = (loose_cost - tight_cost) == headroom
    tracks_used = loose_cost == tight_cost
    assert tracks_declared != tracks_used, (
        f"a rule-group reference's cost tracks neither the group's declared capacity (expected a "
        f"{headroom} WCU difference) nor its used capacity (expected no difference): "
        f"tight(declared={groups['tight']['declared']})={tight_cost}, "
        f"loose(declared={groups['loose']['declared']})={loose_cost}, rules cost {used}"
    )

    # ---- a MANAGED rule group reference: the cost comes from DescribeManagedRuleGroup, and the
    # version comes from ListAvailableManagedRuleGroupVersions. No literal of either kind.
    vendor, group = "AWS", "AWSManagedRulesCommonRuleSet"
    versions = _retry_transient(lambda: w.list_available_managed_rule_group_versions(
        VendorName=vendor, Name=group, Scope=SCOPE, Limit=50))
    default_version = versions["CurrentDefaultVersion"]
    published = {v["Name"] for v in versions.get("Versions", [])}
    assert default_version in published, (
        f"the vendor's CurrentDefaultVersion {default_version!r} is not among the versions it "
        f"publishes {sorted(published)!r}"
    )

    described = _retry_transient(lambda: w.describe_managed_rule_group(
        VendorName=vendor, Name=group, Scope=SCOPE))
    managed_capacity = described["Capacity"]
    assert managed_capacity > 0, (
        f"DescribeManagedRuleGroup reported a non-positive capacity for {group}: "
        f"{managed_capacity!r}"
    )

    described_default = _retry_transient(lambda: w.describe_managed_rule_group(
        VendorName=vendor, Name=group, Scope=SCOPE, VersionName=default_version))
    assert described_default["Capacity"] == managed_capacity, (
        f"an UNPINNED managed rule group reference is documented to resolve to the vendor's "
        f"default version, but the two descriptions disagree on capacity: unpinned="
        f"{managed_capacity!r}, {default_version}={described_default['Capacity']!r}"
    )

    managed_rule = {"Name": "managedref", "Priority": 1,
                    "Statement": {"ManagedRuleGroupStatement": {
                        "VendorName": vendor, "Name": group}},
                    "OverrideAction": {"None": {}}, "VisibilityConfig": _vis("managedref")}
    managed_cost = _retry_transient(lambda: w.check_capacity(
        Scope=SCOPE, Rules=[managed_rule]))["Capacity"]
    assert managed_cost == managed_capacity, (
        f"CheckCapacity priced a reference to {group} at {managed_cost} WCU while "
        f"DescribeManagedRuleGroup reports the group's capacity as {managed_capacity}; the two "
        f"must agree, and neither number may be pinned by the check"
    )

    # ---- the sum: a web ACL over a leaf, an own-group reference and a managed reference must
    # report exactly the sum of the three per-rule figures CheckCapacity gave in THIS run.
    leaf = {"Name": "leaf", "Priority": 2,
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
            "Action": {"Count": {}}, "VisibilityConfig": _vis("leaf")}
    leaf_cost = _retry_transient(lambda: w.check_capacity(
        Scope=SCOPE, Rules=[leaf]))["Capacity"]

    rules = [_ref_rule(groups["tight"]["arn"]), managed_rule, leaf]
    expected = tight_cost + managed_cost + leaf_cost
    combined = _retry_transient(lambda: w.check_capacity(Scope=SCOPE, Rules=rules))["Capacity"]
    assert combined == expected, (
        f"CheckCapacity over [own-group ref, managed ref, leaf] returned {combined} WCU but the "
        f"three priced individually sum to {expected} "
        f"({tight_cost} + {managed_cost} + {leaf_cost}); reference costs are not additive"
    )

    acl_name = "sim2realbehavwafacl" + _tok(10)
    created = _retry_transient(lambda: w.create_web_acl(
        Name=acl_name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=rules,
        VisibilityConfig=_vis(acl_name[:100]),
        Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w.get_web_acl, w.delete_web_acl,
                                          acl_name, created["Id"], "WebACL"))

    # A different operation than the mutation must report the same derived number.
    stored = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=created["Id"])["WebACL"]
    assert stored["Capacity"] == combined, (
        f"GetWebACL reports Capacity {stored['Capacity']} for a web ACL whose rules CheckCapacity "
        f"priced at {combined} in this same run; the two operations must agree"
    )
    stored_names = {r["Name"] for r in stored.get("Rules", [])}
    assert stored_names == {"groupref", "managedref", "leaf"}, (
        f"the web ACL did not store the three rules whose capacities were summed: "
        f"{sorted(stored_names)!r}"
    )
    listed = {s["Name"] for s in _list_all(w.list_web_acls, "WebACLs")}
    assert acl_name in listed, (
        f"the created web ACL {acl_name!r} is absent from ListWebACLs, so the capacity it "
        f"reports describes nothing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
