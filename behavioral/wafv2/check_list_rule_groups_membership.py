"""list-rule-groups-membership."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-rule-groups-membership"
GROUP = 'listing'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav-waf-rg-"},
]

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

_TEARDOWN_RETRY_CODES = (
    "WAFAssociatedItemException", "WAFOptimisticLockException", "WAFUnavailableEntityException"
)

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token)."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    deadline = time.monotonic() + 25.0
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            # A reference or lock-token race still settling is retried; anything else raises.
            if code not in _TEARDOWN_RETRY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

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

def _create_rule_group(ctx, w, name=None, capacity=5, rules=None, scope=SCOPE):
    """Create a RuleGroup (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-rg-")
    created = _retry_transient(
        lambda: w.create_rule_group(
            Name=name, Scope=scope, Capacity=capacity, Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=_TAGS_KV,
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", name, scope, created["Id"]))
    return created

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRuleGroups returns the created rule group summary."""
    w = ctx.client("wafv2")
    summary = _create_rule_group(ctx, w, capacity=5)
    items = _list_all(w.list_rule_groups, "RuleGroups")
    match = [s for s in items if s["Name"] == summary["Name"]]
    assert len(match) == 1, f"expected 1 entry for {summary['Name']}, got {len(match)}"
    assert match[0]["Id"] == summary["Id"], (
        f"expected Id {summary['Id']} for {summary['Name']}, got {match[0]['Id']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
