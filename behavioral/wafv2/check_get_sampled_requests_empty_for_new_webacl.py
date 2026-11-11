"""get-sampled-requests-empty-for-new-webacl."""
from __future__ import annotations

import time
import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-sampled-requests-empty-for-new-webacl"
GROUP = 'traffic'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException",
     "WAFNonexistentItemException"}
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

def _create_web_acl(ctx, w, name=None, rules=None, default_action=None, scope=SCOPE):
    """Create a WebACL (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-acl-")
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction=default_action or {"Allow": {}},
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, created["Id"]))
    return created

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSampledRequests over a window with no traffic returns an empty sample, not an error."""
    w = ctx.client("wafv2")
    summary = _create_web_acl(ctx, w)
    now = datetime.datetime.now(datetime.timezone.utc)
    window = {"StartTime": now - datetime.timedelta(hours=1), "EndTime": now}

    resp = _retry_transient(
        lambda: w.get_sampled_requests(
            WebAclArn=summary["ARN"],
            RuleMetricName="Default_Action",
            Scope=SCOPE,
            TimeWindow=window,
            MaxItems=10,
        )
    )
    assert resp["SampledRequests"] == [], resp["SampledRequests"]
    assert resp["PopulationSize"] == 0, resp["PopulationSize"]
    returned_start = resp["TimeWindow"]["StartTime"]
    drift = abs((returned_start - window["StartTime"]).total_seconds())
    assert drift <= 30, (
        f"in-range StartTime was altered: requested {window['StartTime']}, got {returned_start}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
