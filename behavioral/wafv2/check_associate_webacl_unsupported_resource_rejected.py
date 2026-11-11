"""associate-webacl-unsupported-resource-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-webacl-unsupported-resource-rejected"
GROUP = 'overly-permissive'
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
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, created["Id"]))
    return created

def _safe_disassociate(w, resource_arn):
    try:
        w.disassociate_web_acl(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise

def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed: {last!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateWebACL with an unsupported resource-type ARN is rejected with
    WAFInvalidParameterException, while the same WebACL associates with a Cognito user pool
    (the positive control separates "unsupported type" from "AssociateWebACL is broken")."""
    w = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")
    summary = _create_web_acl(ctx, w)
    bad_resource = f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-waf-bucket-')}"

    code, message = _error_stable(
        lambda: w.associate_web_acl(
            WebACLArn=summary["ARN"], ResourceArn=bad_resource
        )
    )
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: The ARN isn't valid. A valid ARN begins with arn: and includes other "
        f"information separated by colons or slashes., field: RESOURCE_ARN, parameter: {bad_resource}"
    ), message

    pool_name = ctx.unique_name("sim2real-behav-waf-pool-")
    pool = cognito.create_user_pool(PoolName=pool_name)["UserPool"]
    pool_arn = pool["Arn"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool["Id"]))
    ctx.on_cleanup(lambda: _safe_disassociate(w, pool_arn))

    # A just-created user pool can stay unresolvable to WAF (WAFUnavailableEntityException) past 60 s.
    _retry_transient(
        lambda: w.associate_web_acl(WebACLArn=summary["ARN"], ResourceArn=pool_arn), attempts=30
    )
    observed = _poll_until(
        lambda: w.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL"),
        lambda v: v is not None,
    )
    assert observed["ARN"] == summary["ARN"], observed

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
