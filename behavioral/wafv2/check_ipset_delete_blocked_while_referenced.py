"""ipset-delete-blocked-while-referenced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipset-delete-blocked-while-referenced"
GROUP = 'ipset'
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

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (code, HTTP status, message) of the first NON-transient failure of fn.
    Transient WAFv2 codes are retried rather than reported, so an assertion about a
    semantic error is never polluted by throttling or propagation delay. A call that
    succeeds raises AssertionError: the caller expects a refusal."""
    for attempt in range(attempts):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            err = resp.get("Error", {}) if isinstance(resp, dict) else {}
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, resp["ResponseMetadata"]["HTTPStatusCode"], err.get("Message", "")
            time.sleep(delay)
            continue
        raise AssertionError("expected the call to be refused, but it succeeded")
    raise AssertionError("unreachable: every attempt returns or raises")

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token)."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    try:
        lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
        deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "WAFNonexistentItemException":
            raise

def _list_ip_set_ids(w, scope):
    """Every IPSet id in *scope*, following NextMarker."""
    ids, kwargs = set(), {"Scope": scope, "Limit": 100}
    while True:
        page = w.list_ip_sets(**kwargs)
        ids.update(item["Id"] for item in page["IPSets"])
        marker = page.get("NextMarker")
        if not marker or not page["IPSets"]:
            return ids
        kwargs["NextMarker"] = marker

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

def _ipset_reference_statement(arn):
    return {"IPSetReferenceStatement": {"ARN": arn}}

def _create_ipset(ctx, w, name=None, addresses=None, scope=SCOPE):
    """Create an IPSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-ips-")
    addresses = addresses if addresses is not None else ["10.0.0.0/8"]
    summary = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=addresses,
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, scope, summary["Id"]))
    return summary

def _create_rulegroup(ctx, w, name=None, capacity=100, rules=None, scope=SCOPE):
    """Create a RuleGroup (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-rg-")
    summary = _retry_transient(
        lambda: w.create_rule_group(
            Name=name, Scope=scope, Capacity=capacity, Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")[:128]),
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", name, scope, summary["Id"]))
    return summary


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIPSet on a set still referenced by a Rule in a RuleGroup must
    fail with WAFAssociatedItemException; after the reference is removed,
    delete succeeds."""
    w = ctx.client("wafv2")
    ipset = _create_ipset(ctx, w, addresses=["203.0.113.0/24"])
    rulegroup_name = ctx.unique_name("sim2real-behav-waf-rg-")
    rules = [
        {
            "Name": "block-ipset",
            "Priority": 0,
            "Statement": _ipset_reference_statement(ipset["ARN"]),
            "Action": {"Block": {}},
            "VisibilityConfig": _visibility_config("blockipset"),
        }
    ]
    rg = _create_rulegroup(ctx, w, name=rulegroup_name, capacity=10, rules=rules)

    ip_got = w.get_ip_set(Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"])
    code, status, message = _error_stable(
        lambda: w.delete_ip_set(
            Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"], LockToken=ip_got["LockToken"]
        )
    )
    assert (code, status) == ("WAFAssociatedItemException", 400), (
        f"DeleteIPSet on a referenced set: expected WAFAssociatedItemException/400, got {code}/{status}"
    )
    expected_message = "AWS WAF couldn’t perform the operation because your resource is being used by another resource or it’s associated with another resource."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    still_there = w.get_ip_set(Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"])
    assert still_there["IPSet"]["Id"] == ipset["Id"], (
        f"DeleteIPSet was rejected, so an independent GetIPSet must still find it: {still_there!r}"
    )

    rg_got = w.get_rule_group(Name=rg["Name"], Scope=SCOPE, Id=rg["Id"])
    _retry_transient(
        lambda: w.update_rule_group(
            Name=rg["Name"], Scope=SCOPE, Id=rg["Id"], Rules=[],
            VisibilityConfig=_visibility_config("blockipset"), LockToken=rg_got["LockToken"],
        )
    )

    ip_got2 = w.get_ip_set(Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"])
    _retry_transient(
        lambda: w.delete_ip_set(
            Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"], LockToken=ip_got2["LockToken"]
        )
    )

    code_gone, status_gone, message_gone = _error_stable(
        lambda: w.get_ip_set(Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"])
    )
    assert (code_gone, status_gone) == ("WAFNonexistentItemException", 400), (
        f"an independent GetIPSet after the successful delete must report the ipset gone; "
        f"got {code_gone}/{status_gone}"
    )
    expected_message = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."
    assert message_gone == expected_message, f"expected the message {expected_message!r}, got {message_gone!r}"
    assert ipset["Id"] not in _list_ip_set_ids(w, SCOPE), "the deleted IPSet is still listed"

    code_mutate_dead, status_mutate_dead, message_mutate_dead = _error_stable(
        lambda: w.update_ip_set(
            Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"],
            Addresses=["203.0.113.0/24"],
            LockToken="00000000-0000-0000-0000-000000000000",
        )
    )
    assert (code_mutate_dead, status_mutate_dead) == ("WAFNonexistentItemException", 400), (
        f"a mutation on the deleted ipset's id must also fail not-found; got {code_mutate_dead}/{status_mutate_dead}"
    )
    expected_message = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."
    assert message_mutate_dead == expected_message, f"expected the message {expected_message!r}, got {message_mutate_dead!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
