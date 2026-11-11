"""permission-policy-invalid-document-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "permission-policy-invalid-document-rejected"
GROUP = 'permission'
SERVICES = ['wafv2']

# REGIONAL is usable from any endpoint/region; CLOUDFRONT scope requires us-east-1.
SCOPE = "REGIONAL"
_NOT_FOUND = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

# Transient WAF error codes that mean "the resource you referenced exists but hasn't
# propagated to every WAF control-plane replica yet". Real AWS raises these for a few
# seconds/minutes after a create; they are NOT the behavior under test.
TRANSIENT_CODES = ("WAFUnavailableEntityException",)

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _retry_waf(fn, *, codes=TRANSIENT_CODES, timeout_s=150.0, interval_s=5.0):
    """Call fn(), retrying while it raises one of the transient WAF codes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error_stable(fn, *, transient=TRANSIENT_CODES, timeout_s=150.0, interval_s=5.0):
    """Call fn(); return the botocore Error (Code, Message), retrying while the code is
    transient, so a freshly created WAF entity yields the semantic rejection, not the
    propagation-lag one. An unexpected SUCCESS raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message")
            if code not in transient or time.monotonic() >= deadline:
                return code, message
            time.sleep(interval_s)
            continue
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _delete_locked_rule_group(w, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token)."""
    try:
        lt = w.get_rule_group(Name=name, Scope=scope, Id=id_)["LockToken"]
        w.delete_rule_group(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise


def _create_rule_group(w, ctx, capacity=10, rules=None, scope=SCOPE):
    """CreateRuleGroup (through the transient-propagation retry) + register teardown."""
    name = ctx.unique_name("sim2real-behav-waf-rg-")
    summary = _retry_waf(
        lambda: w.create_rule_group(
            Name=name,
            Scope=scope,
            Capacity=capacity,
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name),
            Tags=_TAGS_KV,
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked_rule_group(w, name, scope, summary["Id"]))
    return summary


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutPermissionPolicy with a malformed policy document must be rejected."""
    w = ctx.client("wafv2")
    rg_summary = _create_rule_group(w, ctx, capacity=10, rules=[])
    arn = rg_summary["ARN"]
    # A successfully attached policy would block the rule-group delete, so tear it down
    # first (cleanups run LIFO). This check expects PutPermissionPolicy to be REJECTED.
    def _drop_policy():
        # Tolerates not-found: the expected outcome is that no policy was ever attached.
        try:
            w.delete_permission_policy(ResourceArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_drop_policy)

    code, message = _error_stable(
        lambda: w.put_permission_policy(ResourceArn=arn, Policy="{not valid json"),
        transient=("WAFUnavailableEntityException", "WAFNonexistentItemException"),
    )
    assert code == "WAFInvalidPermissionPolicyException", code
    assert message == (
        "The policy specification doesn't meet the requirements to be attached to an "
        "AWS WAF resource."
    ), message

    # Independent read at the destination: the rejected document must not have been
    # attached. GetPermissionPolicy on a rule group with no policy raises
    # WAFNonexistentItemException.
    no_policy_code, no_policy_message = _error_stable(
        lambda: w.get_permission_policy(ResourceArn=arn)
    )
    assert no_policy_code == "WAFNonexistentItemException", no_policy_code
    assert no_policy_message == _NOT_FOUND, no_policy_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
