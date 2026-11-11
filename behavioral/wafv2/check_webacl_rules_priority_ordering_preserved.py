"""webacl-rules-priority-ordering-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-rules-priority-ordering-preserved"
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
    """WebACL.Rules must be returned ordered by Priority (evaluation order),
    regardless of the order the Rules were supplied in the request -- on both
    CreateWebACL and UpdateWebACL."""
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-acl-")
    rules = [
        {
            "Name": "third",
            "Priority": 2,
            "Statement": {"ByteMatchStatement": {
                "SearchString": b"c",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }},
            "Action": {"Count": {}},
            "VisibilityConfig": _visibility_config("third"),
        },
        {
            "Name": "first",
            "Priority": 0,
            "Statement": {"ByteMatchStatement": {
                "SearchString": b"a",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }},
            "Action": {"Count": {}},
            "VisibilityConfig": _visibility_config("first"),
        },
        {
            "Name": "second",
            "Priority": 1,
            "Statement": {"ByteMatchStatement": {
                "SearchString": b"b",
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }},
            "Action": {"Count": {}},
            "VisibilityConfig": _visibility_config("second"),
        },
    ]
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=rules,
            VisibilityConfig=_visibility_config(name.replace("-", "")),
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, SCOPE, created["Id"]))

    got = w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    returned_names = [r["Name"] for r in got["WebACL"]["Rules"]]
    assert returned_names == ["first", "second", "third"], (
        f"expected Rules ordered ascending by Priority ['first', 'second', "
        f"'third'], got {returned_names}"
    )
    returned_priorities = [r["Priority"] for r in got["WebACL"]["Rules"]]
    assert returned_priorities == [0, 1, 2], (
        f"expected each rule's own Priority preserved as [0, 1, 2], got {returned_priorities}"
    )

    # UpdateWebACL: resubmit the same rules in yet another request order with
    # different Priority values. The same re-normalization -- by the NEW
    # priorities, not the request order or the old priorities -- must hold.
    lock_token = got["LockToken"]
    updated_rules = [
        {**rules[1], "Priority": 12},  # "first" -> 12
        {**rules[2], "Priority": 4},   # "second" -> 4
        {**rules[0], "Priority": 8},   # "third" -> 8
    ]
    updated = _retry_transient(
        lambda: w.update_web_acl(
            Name=name, Scope=SCOPE, Id=created["Id"], LockToken=lock_token,
            DefaultAction={"Allow": {}}, Rules=updated_rules,
            VisibilityConfig=_visibility_config(name.replace("-", "")),
        )
    )
    assert updated["NextLockToken"] and updated["NextLockToken"] != lock_token, (
        f"expected a fresh non-empty NextLockToken different from {lock_token!r}, "
        f"got {updated.get('NextLockToken')!r}"
    )

    got2 = w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    returned_names2 = [r["Name"] for r in got2["WebACL"]["Rules"]]
    assert returned_names2 == ["second", "third", "first"], (
        f"expected Rules re-normalized to ascending-Priority order "
        f"['second', 'third', 'first'] (Priority 4, 8, 12) after UpdateWebACL, "
        f"got {returned_names2}"
    )
    returned_priorities2 = {r["Name"]: r["Priority"] for r in got2["WebACL"]["Rules"]}
    assert returned_priorities2 == {"first": 12, "second": 4, "third": 8}, (
        f"expected updated Priority values {{'first': 12, 'second': 4, "
        f"'third': 8}}, got {returned_priorities2}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
