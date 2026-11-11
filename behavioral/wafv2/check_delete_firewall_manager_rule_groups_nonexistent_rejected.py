"""delete-firewall-manager-rule-groups-nonexistent-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-firewall-manager-rule-groups-nonexistent-rejected"
GROUP = 'association'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _error_stable(fn, attempts=10, delay=6.0):
    """(code, message) of the first non-transient failure, retrying throttling and propagation
    errors; a call that succeeds fails the check."""
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

def _retry_transient(fn, attempts=12, delay=6.0):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in _TRANSIENT_CODES:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

def _delete_locked_web_acl(w, name, scope, id_):
    try:
        lt = w.get_web_acl(Name=name, Scope=scope, Id=id_)["LockToken"]
        w.delete_web_acl(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFirewallManagerRuleGroups on an unknown WebACL ARN is WAFNonexistentItemException,
    while on a real WebACL it succeeds and rotates the lock token seen by GetWebACL."""
    w = ctx.client("wafv2")
    account = ctx.account

    name = ctx.unique_name("sim2real-behav-waf-acl-")
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig={
                "SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                "MetricName": name.replace("-", ""),
            },
            Tags=[{"Key": "sim2real", "Value": name}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked_web_acl(w, name, SCOPE, created["Id"]))

    before = w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    lock_token = before["LockToken"]

    result = _retry_transient(
        lambda: w.delete_firewall_manager_rule_groups(
            WebACLArn=created["ARN"], WebACLLockToken=lock_token
        )
    )
    assert result["NextWebACLLockToken"] != lock_token, (
        f"expected token rotation on a real WebACL, got unchanged {lock_token!r}"
    )

    after = w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    assert after["LockToken"] == result["NextWebACLLockToken"], (
        f"independent read did not observe the rotated token: "
        f"read {after['LockToken']!r}, expected {result['NextWebACLLockToken']!r}"
    )

    fake_arn = (
        f"arn:aws:wafv2:{ctx.region}:{account}:regional/webacl/"
        f"{ctx.unique_name('sim2real-behav-waf-ghost-acl-')}/00000000-0000-0000-0000-000000000000"
    )
    code, message = _error_stable(
        lambda: w.delete_firewall_manager_rule_groups(
            WebACLArn=fake_arn, WebACLLockToken="00000000-0000-0000-0000-000000000000"
        )
    )
    assert code == "WAFNonexistentItemException", code
    assert message == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
