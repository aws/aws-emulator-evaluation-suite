"""rulegroup-nonexistent-reference-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rulegroup-nonexistent-reference-rejected"
GROUP = 'rulegroup'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable). Used only for the positive control:
    the negative leg's ARN is fabricated and can never resolve, so it is never
    retried there."""
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

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

def _ipset_reference_statement(arn):
    return {"IPSetReferenceStatement": {"ARN": arn}}

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

def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token). Already
    gone is clean; a reference still being released or a transient error is retried for 15 s."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    retryable = _TRANSIENT_CODES | {"WAFAssociatedItemException", "WAFOptimisticLockException"}
    deadline = time.monotonic() + 15.0
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            if code not in retryable or time.monotonic() >= deadline:
                raise
        time.sleep(2)


_NOT_FOUND_MESSAGE = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRuleGroup referencing a nonexistent IPSet ARN is rejected with
    WAFNonexistentItemException (WAF never persists a dangling reference); the same
    shape pointed at a real IPSet succeeds, isolating the dangling ARN as the cause."""
    w = ctx.client("wafv2")

    ipset_name = ctx.unique_name("sim2real-behav-waf-ips-")
    ipset = _retry_transient(
        lambda: w.create_ip_set(
            Name=ipset_name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["203.0.113.0/24"]
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", ipset_name, SCOPE, ipset["Id"]))

    control_name = ctx.unique_name("sim2real-behav-waf-rg-control-")
    control_created = _retry_transient(
        lambda: w.create_rule_group(
            Name=control_name, Scope=SCOPE, Capacity=10,
            Rules=[{
                "Name": "match-real-ipset",
                "Priority": 0,
                "Statement": _ipset_reference_statement(ipset["ARN"]),
                "Action": {"Count": {}},
                "VisibilityConfig": _visibility_config(control_name.replace("-", "")),
            }],
            VisibilityConfig=_visibility_config(control_name.replace("-", "") + "g"),
        )
    )["Summary"]
    ctx.on_cleanup(
        lambda: _delete_locked(w, "rule_group", control_name, SCOPE, control_created["Id"])
    )

    control_got = w.get_rule_group(Name=control_name, Scope=SCOPE, Id=control_created["Id"])
    control_stmt = control_got["RuleGroup"]["Rules"][0]["Statement"]
    assert control_stmt["IPSetReferenceStatement"]["ARN"] == ipset["ARN"], (
        f"positive control: a rule group referencing a REAL IPSet did not round-trip "
        f"the reference: {control_stmt}"
    )

    rg_name = ctx.unique_name("sim2real-behav-waf-rg-")
    bogus_arn = (
        f"arn:aws:wafv2:{ctx.region}:{_account_id(ctx)}:regional/ipset/"
        f"{ctx.unique_name('sim2real-behav-missing-')}/00000000-0000-0000-0000-000000000000"
    )
    rules = [
        {
            "Name": "dangling-ref",
            "Priority": 0,
            "Statement": _ipset_reference_statement(bogus_arn),
            "Action": {"Block": {}},
            "VisibilityConfig": _visibility_config("danglingref"),
        }
    ]

    code = message = None
    try:
        resp = w.create_rule_group(
            Name=rg_name, Scope=SCOPE, Capacity=10, Rules=rules,
            VisibilityConfig=_visibility_config(rg_name.replace("-", "")),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = exc.response.get("Error", {}).get("Message")
    else:
        # Overly-permissive backend accepted the dangling reference. Capture the REAL Id from
        # the create response so teardown can actually delete it (was "unknown" -> get_rule_group
        # fails -> the rule group leaks). Never reached on real AWS (the create is rejected).
        rg_id = resp["Summary"]["Id"]
        ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", rg_name, SCOPE, rg_id))

    assert code == "WAFNonexistentItemException", (
        f"dangling IPSet reference was not rejected as a missing reference: {code}"
    )
    assert message == _NOT_FOUND_MESSAGE, message

    listed = _list_all(w.list_rule_groups, "RuleGroups")
    assert not any(s["Name"] == rg_name for s in listed), (
        f"rule group {rg_name} with a dangling IPSet reference should not have been persisted"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
