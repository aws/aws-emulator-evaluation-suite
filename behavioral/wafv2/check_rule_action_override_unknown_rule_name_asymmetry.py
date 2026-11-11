"""rule-action-override-unknown-rule-name-asymmetry."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "rule-action-override-unknown-rule-name-asymmetry"
GROUP = 'overly-permissive'
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


def _error_code(fn):
    """Run fn, expecting failure; return (code, response). A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - the error IS the assertion target
        resp = getattr(exc, "response", None)
        if not isinstance(resp, dict):
            raise
        return resp.get("Error", {}).get("Code", ""), resp
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _delete_locked(w, kind, name, scope, id_):
    """Delete a WAFv2 resource, ALWAYS re-fetching its LockToken inside this call.

    A LockToken captured at create time is invalidated by every intervening update, and
    DeleteWebACL/DeleteRuleGroup with a stale token fails with
    WAFOptimisticLockException -- which means the resource survives and keeps billing.
    Fetching the token here, at delete time, is what makes teardown reliable.
    """
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    cur = _retry_transient(lambda: getter(Name=name, Scope=scope, Id=id_))
    token = cur["LockToken"]
    _retry_transient(
        lambda: deleter(Name=name, Scope=scope, Id=id_, LockToken=token),
        codes=_TRANSIENT_CODES | {"WAFAssociatedItemException"},
    )

_OWN_RULE = "own-rule"
_UNKNOWN_RULE = "no-such-rule-in-this-group"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateWebACL fails (WAFInvalidParameterException, HTTP 400, exact message) on an override naming an
    unknown rule of a customer-owned rule group, leaving overrides and LockToken unchanged; a valid
    update lands, and the same unknown name on a managed rule group is accepted.
    """
    w = ctx.client("wafv2")

    # ---- setup: a customer-owned rule group with exactly one, known rule name.
    rg_name = ctx.unique_name("sim2real-behav-waf-rg-")[:128]
    rg = _retry_transient(lambda: w.create_rule_group(
        Name=rg_name, Scope=SCOPE, Capacity=10,
        VisibilityConfig=_visibility_config("rgmetric"),
        Rules=[{
            "Name": _OWN_RULE,
            "Priority": 0,
            "Statement": {"GeoMatchStatement": {"CountryCodes": ["AQ"]}},
            "Action": {"Block": {}},
            "VisibilityConfig": _visibility_config("ownrule"),
        }],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    ))["Summary"]
    # Registered FIRST so that LIFO teardown deletes it LAST, after the web ACL that
    # references it (a referenced rule group cannot be deleted).
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", rg_name, SCOPE, rg["Id"]))

    def _rg_reference(overrides):
        return {
            "Name": "rgref",
            "Priority": 0,
            "Statement": {"RuleGroupReferenceStatement": {
                "ARN": rg["ARN"], "RuleActionOverrides": overrides,
            }},
            "OverrideAction": {"None": {}},
            "VisibilityConfig": _visibility_config("rgref"),
        }

    valid_override = [{"Name": _OWN_RULE, "ActionToUse": {"Count": {}}}]
    bad_override = [{"Name": _UNKNOWN_RULE, "ActionToUse": {"Count": {}}}]

    # ---- setup: a web ACL referencing that rule group with a VALID override.
    acl_name = ctx.unique_name("sim2real-behav-waf-acl-")[:128]
    acl = _retry_transient(lambda: w.create_web_acl(
        Name=acl_name, Scope=SCOPE, DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("aclmetric"),
        Rules=[_rg_reference(valid_override)],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", acl_name, SCOPE, acl["Id"]))

    # The valid override round-trips: this is the control, and it establishes that the
    # ONLY thing wrong with the mutation below is the rule name.
    got = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    stored = got["WebACL"]["Rules"][0]["Statement"]["RuleGroupReferenceStatement"]
    assert stored["RuleActionOverrides"] == valid_override, stored
    token_before = got["LockToken"]

    # ---- break exactly one thing: the override names a rule the group does not have.
    code, resp = _error_code(lambda: w.update_web_acl(
        Name=acl_name, Scope=SCOPE, Id=acl["Id"], LockToken=token_before,
        DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("aclmetric"),
        Rules=[_rg_reference(bad_override)],
    ))
    # Real AWS: WAFInvalidParameterException, field RULE_GROUP_REFERENCE_STATEMENT, and a
    # message naming the offending rule name.
    assert code == "WAFInvalidParameterException", (
        f"expected WAFInvalidParameterException for an unknown override rule name, got "
        f"{code}: {resp.get('Error')}"
    )
    err_message = resp.get("Error", {}).get("Message", "")
    assert err_message == (
        "Error reason: AWS WAF couldn't find a resource that a parameter references., "
        f"field: RULE_GROUP_REFERENCE_STATEMENT, parameter: {_UNKNOWN_RULE}"
    ), err_message
    assert resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400, resp.get(
        "ResponseMetadata", {}
    ).get("HTTPStatusCode")

    # ---- the effect is absent: the stored web ACL is byte-for-byte the pre-update one.
    after = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    stored_after = after["WebACL"]["Rules"][0]["Statement"]["RuleGroupReferenceStatement"]
    assert stored_after["RuleActionOverrides"] == valid_override, (
        f"the refused UpdateWebACL still mutated the stored overrides: {stored_after}"
    )
    assert after["LockToken"] == token_before, (
        "the refused UpdateWebACL rotated the LockToken, so it was treated as a "
        "successful write"
    )

    # ---- the control still works: the same update with the valid override succeeds.
    ok = _retry_transient(lambda: w.update_web_acl(
        Name=acl_name, Scope=SCOPE, Id=acl["Id"], LockToken=after["LockToken"],
        DefaultAction={"Block": {}},
        VisibilityConfig=_visibility_config("aclmetric"),
        Rules=[_rg_reference(valid_override)],
    ))
    assert ok["NextLockToken"] != token_before, ok["NextLockToken"]
    control = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    assert control["WebACL"]["DefaultAction"] == {"Block": {}}, \
        control["WebACL"]["DefaultAction"]

    # ---- the other half of the asymmetry: the SAME kind of bogus override name against
    # a MANAGED rule group must be accepted and silently ignored, not refused.
    managed_ref = {
        "Name": "managed",
        "Priority": 1,
        "Statement": {"ManagedRuleGroupStatement": {
            "VendorName": "AWS", "Name": "AWSManagedRulesAmazonIpReputationList",
            "RuleActionOverrides": [
                {"Name": _UNKNOWN_RULE, "ActionToUse": {"Count": {}}}
            ],
        }},
        "OverrideAction": {"None": {}},
        "VisibilityConfig": _visibility_config("managed"),
    }
    tolerated = _retry_transient(lambda: w.update_web_acl(
        Name=acl_name, Scope=SCOPE, Id=acl["Id"], LockToken=control["LockToken"],
        DefaultAction={"Block": {}},
        VisibilityConfig=_visibility_config("aclmetric"),
        Rules=[_rg_reference(valid_override), managed_ref],
    ))
    assert tolerated["NextLockToken"], tolerated
    final = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    assert len(final["WebACL"]["Rules"]) == 2, final["WebACL"]["Rules"]
    # NOTE: whether the ignored override is echoed back by GetWebACL is deliberately not
    # asserted -- the documented contract is only that WAF does not reject it. Asserting
    # acceptance is the whole point: an emulator that validates override names uniformly
    # fails here, and an emulator that validates none of them fails above.


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
