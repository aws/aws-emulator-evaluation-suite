"""list-resources-for-webacl-empty-when-unassociated."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resources-for-webacl-empty-when-unassociated"
GROUP = 'association'
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

#: One teardown's retry window; a check's teardowns together stay inside the 900 s cleanup budget.
_CLEANUP_WAIT_S = 120.0
_CLEANUP_RETRY_CODES = frozenset(
    {"WAFOptimisticLockException", "WAFAssociatedItemException", "WAFUnavailableEntityException"}
)

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token). Gone is done;
    a stale token or a lingering reference is retried every 2 s; anything else raises."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    deadline = time.monotonic() + _CLEANUP_WAIT_S
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            if code not in _CLEANUP_RETRY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)

#: WAFv2 can take minutes to resolve a just-created resource for AssociateWebACL.
_ASSOCIATE_WAIT_S = 240.0

def _associate_when_resolvable(ctx, w, acl_arn, resource_arn):
    """AssociateWebACL, retrying _TRANSIENT_CODES (throttling, WAFUnavailableEntityException,
    WAFInternalErrorException, WAFNonexistentItemException) every 2 s to a deadline capped by the run budget."""
    left = ctx.time_left()
    wait_s = _ASSOCIATE_WAIT_S if left is None else max(1.0, min(_ASSOCIATE_WAIT_S, left - 5.0))
    deadline = time.monotonic() + wait_s
    while True:
        try:
            return w.associate_web_acl(WebACLArn=acl_arn, ResourceArn=resource_arn)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in _TRANSIENT_CODES or time.monotonic() >= deadline:
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
            Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, created["Id"]))
    return created

def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NotFoundException",
            "WAFNonexistentItemException",
        ):
            raise

def _poll_until(probe, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last observed: {last!r}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new WebACL lists no resources of any type; associating an AppSync API lists it under
    APPSYNC only, and disassociating clears it, so the listing tracks real association state."""
    w = ctx.client("wafv2")
    appsync = ctx.client("appsync")
    summary = _create_web_acl(ctx, w)
    resource_types = ("APPLICATION_LOAD_BALANCER", "API_GATEWAY", "APPSYNC")

    def _list(resource_type):
        return _retry_transient(
            lambda: w.list_resources_for_web_acl(
                WebACLArn=summary["ARN"], ResourceType=resource_type
            )
        )["ResourceArns"]

    for resource_type in resource_types:
        arns = _list(resource_type)
        assert arns == [], (resource_type, arns, "expected no resources before any association")

    api = _retry_transient(
        lambda: appsync.create_graphql_api(
            name=ctx.unique_name("sim2real-behav-waf-appsync-"),
            authenticationType="API_KEY",
            tags={"sim2real": CHECK, "sim2real:managed": "true"},
        )
    )["graphqlApi"]
    api_arn, api_id = api["arn"], api["apiId"]
    ctx.on_cleanup(lambda: _safe_call(lambda: appsync.delete_graphql_api(apiId=api_id)))

    _associate_when_resolvable(ctx, w, summary["ARN"], api_arn)
    ctx.on_cleanup(lambda: _safe_call(lambda: w.disassociate_web_acl(ResourceArn=api_arn)))

    _poll_until(
        lambda: api_arn in _list("APPSYNC"),
        description=f"ListResourcesForWebACL(APPSYNC) reporting the associated API {api_arn}",
    )

    for resource_type in ("APPLICATION_LOAD_BALANCER", "API_GATEWAY"):
        arns = _list(resource_type)
        assert arns == [], (
            resource_type, arns,
            "an APPSYNC association must not appear under a different ResourceType",
        )

    _retry_transient(lambda: w.disassociate_web_acl(ResourceArn=api_arn))
    _poll_until(
        lambda: _list("APPSYNC") == [],
        description=f"ListResourcesForWebACL(APPSYNC) clearing {api_arn} after DisassociateWebACL",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
