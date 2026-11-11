"""checkcapacity-wcu-cost-model-and-ceiling."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "checkcapacity-wcu-cost-model-and-ceiling"
GROUP = 'capacity'
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
    """Return (code, message) of the first NON-transient failure. Transient WAFv2 codes
    are retried rather than reported, so an assertion about a semantic error is never
    polluted by throttling or propagation delay. A call that succeeds raises: an
    emulator accepting what AWS refuses must fail loudly, not read as a code mismatch."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            code, message = "", ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
                message = resp.get("Error", {}).get("Message", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, message
            time.sleep(delay)
        else:
            raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")
    raise AssertionError("unreachable")

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

def _sqli_statement(idx=0):
    """A SqliMatchStatement (deliberately expensive, ~20 WCU each); idx varies the
    inspected header so sibling statements are never byte-identical."""
    return {
        "SqliMatchStatement": {
            "FieldToMatch": {"SingleHeader": {"Name": f"x-probe-{idx}"}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
        }
    }

def _expensive_rules(n_rules, per_rule):
    """n_rules rules, each an OrStatement of per_rule Sqli statements (~n*per*20 WCU)."""
    rules = []
    for i in range(n_rules):
        if per_rule == 1:
            statement = _sqli_statement(i)
        else:
            statement = {
                "OrStatement": {
                    "Statements": [_sqli_statement(i * per_rule + j) for j in range(per_rule)]
                }
            }
        rules.append({
            "Name": f"expensive-{i}",
            "Priority": i,
            "Statement": statement,
            "Action": {"Count": {}},
            "VisibilityConfig": _visibility_config(f"expensive{i}"),
        })
    return rules

def _cheap_rules(n_rules=1):
    """Rules built from the cheapest statement type (ByteMatch, ~1 WCU)."""
    rules = []
    for i in range(n_rules):
        rules.append({
            "Name": f"cheap-{i}",
            "Priority": i,
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": f"needle-{i}".encode(),
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "CONTAINS",
                }
            },
            "Action": {"Count": {}},
            "VisibilityConfig": _visibility_config(f"cheap{i}"),
        })
    return rules

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

def _delete_web_acl_by_name(w, name, scope=SCOPE):
    """Best-effort teardown looked up by name rather than Id -- used both for the
    positive-control ACL and as a defensive net for the over-ceiling create attempt,
    which is expected to fail but must not leak if it unexpectedly succeeds."""
    for item in _list_all(w.list_web_acls, "WebACLs", scope=scope):
        if item["Name"] == name:
            try:
                lt = w.get_web_acl(Name=name, Scope=scope, Id=item["Id"])["LockToken"]
                w.delete_web_acl(Name=name, Scope=scope, Id=item["Id"], LockToken=lt)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                    raise
            return


@tags("axis:happy-path", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CheckCapacity is additive and statement-type sensitive (three SQLi statements cost three times
    one, a cheaper statement costs less), and CreateWebACL with rules over 5000 WCU fails with
    WAFInvalidParameterException and the exact message and creates no WebACL.
    """
    w = ctx.client("wafv2")
    unit = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=_expensive_rules(1, 1))
    )["Capacity"]
    assert unit >= 20, f"SqliMatchStatement should cost >=20 WCU, got {unit}"

    cap3 = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=_expensive_rules(3, 1))
    )["Capacity"]
    assert cap3 == 3 * unit, f"expected additive cost {3 * unit}, got {cap3}"

    cheap = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=_cheap_rules(1))
    )["Capacity"]
    assert 0 < cheap < unit, (cheap, unit)

    block_cost = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=_expensive_rules(1, 10))
    )["Capacity"]
    assert block_cost > 0, f"a 10-statement OrStatement rule must cost >0 WCU, got {block_cost}"
    n_rules = (15000 // block_cost) + 5
    huge = _expensive_rules(n_rules, 10)

    # Positive control: CreateWebACL succeeds for a rule set far under the ceiling, so the
    # rejection below is attributable to the WCU ceiling and not to CreateWebACL being broken
    # or denied outright for these credentials.
    control_name = ctx.unique_name("sim2real-behav-waf-acl-ctrl-")
    control = _retry_transient(
        lambda: w.create_web_acl(
            Name=control_name,
            Scope=SCOPE,
            DefaultAction={"Allow": {}},
            Rules=_cheap_rules(1),
            VisibilityConfig=_visibility_config(control_name.replace("-", "")),
            Tags=[{"Key": "Team", "Value": "sim2real"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_web_acl_by_name(w, control_name))
    control_listed = _list_all(w.list_web_acls, "WebACLs")
    assert any(s["Name"] == control_name for s in control_listed), (
        f"positive control web ACL {control_name!r} (Id {control['Id']}) did not appear in "
        f"ListWebACLs"
    )

    # CheckCapacity reports an over-ceiling rule set's cost rather than refusing it; the
    # ceiling is enforced by CreateWebACL below.
    total = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=huge)
    )["Capacity"]
    assert total == n_rules * block_cost, f"expected additive cost {n_rules * block_cost}, got {total}"

    assert total > 5000, f"premise broken: {n_rules} rules only cost {total} WCU"

    name = ctx.unique_name("sim2real-behav-waf-acl-")
    ctx.on_cleanup(lambda: _delete_web_acl_by_name(w, name))
    code, message = _error_stable(
        lambda: w.create_web_acl(
            Name=name,
            Scope=SCOPE,
            DefaultAction={"Allow": {}},
            Rules=huge,
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=[{"Key": "Team", "Value": "sim2real"}],
        )
    )
    assert code == "WAFInvalidParameterException", (
        f"web ACL of {total} WCU (ceiling 5000) was not rejected: {code}"
    )
    assert message == (
        "Error reason: You exceeded the capacity limit for a rule group or web ACL., "
        f"field: WEB_ACL, parameter: {total}"
    ), message

    listed = _list_all(w.list_web_acls, "WebACLs")
    assert not any(s["Name"] == name for s in listed), (
        f"web ACL {name!r} was rejected with {code!r} but still appears in ListWebACLs"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
