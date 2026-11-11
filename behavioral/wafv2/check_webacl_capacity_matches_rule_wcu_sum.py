"""webacl-capacity-matches-rule-wcu-sum."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-capacity-matches-rule-wcu-sum"
GROUP = 'webacl'
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

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetWebACL.WebACL.Capacity must reflect the actual WCU cost of the
    configured Rules (as independently reported by CheckCapacity for the
    same Rules), not a placeholder/static value."""
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-acl-")
    rule_statement = {
        "ByteMatchStatement": {
            "SearchString": b"attack",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "CONTAINS",
        }
    }
    rules = [
        {
            "Name": "byte-match",
            "Priority": 0,
            "Statement": rule_statement,
            "Action": {"Block": {}},
            "VisibilityConfig": _visibility_config("bytematch"),
        }
    ]

    expected_capacity = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=rules)
    )["Capacity"]
    assert expected_capacity >= 1, (
        "CheckCapacity must report a real positive WCU cost for a ByteMatchStatement rule",
        expected_capacity,
    )

    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=rules,
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, SCOPE, created["Id"]))

    got = w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    assert got["WebACL"]["Capacity"] == expected_capacity, (
        "GetWebACL.Capacity must match CheckCapacity's independently computed value, not a placeholder",
        got["WebACL"]["Capacity"],
        expected_capacity,
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
