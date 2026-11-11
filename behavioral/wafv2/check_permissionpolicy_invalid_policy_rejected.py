"""permissionpolicy-invalid-policy-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "permissionpolicy-invalid-policy-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFNonexistentItemException's message for a resource with no policy attached.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."
#: WAFInvalidPermissionPolicyException's message for a refused sharing policy.
POLICY_MESSAGE = (
    "The policy specification doesn't meet the requirements to be attached to an AWS WAF resource."
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

def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]

def _create_rulegroup(ctx, w, name=None, capacity=100, rules=None, scope=SCOPE):
    """Create a RuleGroup (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-rg-")
    summary = _retry_transient(
        lambda: w.create_rule_group(
            Name=name, Scope=scope, Capacity=capacity, Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")[:128]),
            Tags=_TAGS_KV,
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", name, scope, summary["Id"]))
    return summary

def _delete_policy_best_effort(w, arn):
    try:
        w.delete_permission_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutPermissionPolicy with a policy missing the Action/Principal shape WAF requires for
    RuleGroup sharing fails with WAFInvalidPermissionPolicyException, while a well-formed
    sharing policy on the same RuleGroup is accepted first (positive control)."""
    w = ctx.client("wafv2")
    rg = _create_rulegroup(ctx, w, capacity=10)
    ctx.on_cleanup(lambda: _delete_policy_best_effort(w, rg["ARN"]))

    principal = f"arn:aws:iam::{_account_id(ctx)}:root"
    valid_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        f'"Principal":{{"AWS":"{principal}"}},'
        '"Action":["wafv2:CreateWebACL","wafv2:UpdateWebACL",'
        '"wafv2:PutFirewallManagerRuleGroups","wafv2:GetRuleGroup"]}]}'
    )
    _retry_transient(
        lambda: w.put_permission_policy(ResourceArn=rg["ARN"], Policy=valid_policy)
    )
    got = w.get_permission_policy(ResourceArn=rg["ARN"])
    assert "wafv2:PutFirewallManagerRuleGroups" in got["Policy"], got["Policy"]
    _retry_transient(
        lambda: w.delete_permission_policy(ResourceArn=rg["ARN"])
    )

    malformed_policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow"}]}'

    code, message = _error_stable(
        lambda: w.put_permission_policy(ResourceArn=rg["ARN"], Policy=malformed_policy)
    )
    assert code == "WAFInvalidPermissionPolicyException", code
    assert message == POLICY_MESSAGE, message

    no_policy_code, no_policy_message = _error_stable(
        lambda: w.get_permission_policy(ResourceArn=rg["ARN"])
    )
    assert no_policy_code == "WAFNonexistentItemException", no_policy_code
    assert no_policy_message == NONEXISTENT_MESSAGE, no_policy_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
