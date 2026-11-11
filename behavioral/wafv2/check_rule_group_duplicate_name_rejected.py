"""rule-group-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-group-duplicate-name-rejected"
GROUP = 'rulegroup'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFDuplicateItemException's message for a reused Name+Scope.
DUPLICATE_MESSAGE = (
    "AWS WAF couldn’t perform the operation because some resource in your request is a "
    "duplicate of an existing one."
)

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
    """Return (code, message) of the first NON-transient failure of fn.
    Transient WAFv2 codes are retried rather than reported, so an assertion about a
    semantic error is never polluted by throttling or propagation delay. A call that
    succeeds raises AssertionError: the caller expects a refusal."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            if not isinstance(resp, dict):
                raise
            err = resp.get("Error", {})
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message", "")
            time.sleep(delay)
            continue
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    raise AssertionError("unreachable: every attempt returns or raises")

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
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", name, scope, created["Id"]))
    return created

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second RuleGroup with the same Name+Scope must fail as duplicate,
    the original RuleGroup must be untouched by the rejected attempt, and a
    genuinely different name must still succeed."""
    w = ctx.client("wafv2")
    summary = _create_rule_group(ctx, w, capacity=5)
    name = summary["Name"]
    rg_id = summary["Id"]

    code, message = _error_stable(
        lambda: w.create_rule_group(
            Name=name, Scope=SCOPE, Capacity=99, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "") + "dup"),
        )
    )
    assert code == "WAFDuplicateItemException", code
    assert message == DUPLICATE_MESSAGE, message

    # The effect of the rejected duplicate must be absent: the original RuleGroup's
    # own capacity is untouched, and there is still exactly one RuleGroup with this name.
    unchanged = _retry_transient(
        lambda: w.get_rule_group(Name=name, Scope=SCOPE, Id=rg_id)
    )["RuleGroup"]
    assert unchanged["Capacity"] == 5, f"expected Capacity=5, got {unchanged['Capacity']!r}"
    matching = [g for g in _list_all(w.list_rule_groups, "RuleGroups") if g["Name"] == name]
    assert len(matching) == 1 and matching[0]["Id"] == rg_id, matching

    # Positive control: a genuinely different name still creates successfully, so the
    # rejection above is specific to the name collision, not a broad failure.
    other = _create_rule_group(ctx, w, capacity=5)
    assert other["Name"] != name, other

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
