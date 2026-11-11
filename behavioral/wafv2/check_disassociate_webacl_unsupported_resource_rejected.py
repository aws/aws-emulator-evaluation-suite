"""disassociate-webacl-unsupported-resource-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disassociate-webacl-unsupported-resource-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

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
    "WAFAssociatedItemException", "WAFOptimisticLockException", "WAFUnavailableEntityException",
    "InvalidParameterException", "TooManyRequestsException",
)

def _safe_call(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise

def _safe_call_retry(fn, timeout_s=24.0):
    """Teardown delete: gone is success; a refusal while the WAFv2 association is still
    being released is retried every 2 s to the deadline; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("WAFNonexistentItemException", "ResourceNotFoundException"):
                return
            if code not in _TEARDOWN_RETRY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _associate_with_retry(w, web_acl_arn, resource_arn, timeout_s=150.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            w.associate_web_acl(WebACLArn=web_acl_arn, ResourceArn=resource_arn)
            return
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "WAFUnavailableEntityException":
                raise
            time.sleep(3)
    raise AssertionError(f"AssociateWebACL never succeeded: {last_err}")

def _poll_until(probe, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateWebACL with an unsupported resource-type ARN is rejected, while a real
    association on a supported resource disassociates (the positive control separates
    "rejects this ARN" from "rejects every call")."""
    w = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")

    web_acl_name = ctx.unique_name("sim2real-behav-wacl-")
    summary = w.create_web_acl(
        Name=web_acl_name,
        Scope=SCOPE,
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": web_acl_name,
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Summary"]
    web_acl_arn, web_acl_id = summary["ARN"], summary["Id"]
    ctx.on_cleanup(lambda: _safe_call_retry(lambda: w.delete_web_acl(
        Name=web_acl_name, Scope=SCOPE, Id=web_acl_id,
        LockToken=w.get_web_acl(Name=web_acl_name, Scope=SCOPE, Id=web_acl_id)["LockToken"],
    )))

    pool_name = ctx.unique_name("sim2real-behav-pool-")
    pool = cognito.create_user_pool(
        PoolName=pool_name,
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]
    pool_arn, pool_id = pool["Arn"], pool["Id"]
    ctx.on_cleanup(lambda: _safe_call_retry(lambda: cognito.delete_user_pool(UserPoolId=pool_id)))
    ctx.on_cleanup(lambda: _safe_call(lambda: w.disassociate_web_acl(ResourceArn=pool_arn)))

    _associate_with_retry(w, web_acl_arn, pool_arn)

    def _has_web_acl():
        return w.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL") is not None

    assert _poll_until(_has_web_acl), "positive control: AssociateWebACL never became visible via GetWebACLForResource"

    bad_resource = f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-waf-bucket-')}"
    code, message = _error_stable(lambda: w.disassociate_web_acl(ResourceArn=bad_resource))
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: The ARN isn't valid. A valid ARN begins with arn: and includes other "
        f"information separated by colons or slashes., field: RESOURCE_ARN, parameter: {bad_resource}"
    ), message

    assert _has_web_acl(), "the rejected disassociate on an unrelated ARN must not disturb the real association"

    w.disassociate_web_acl(ResourceArn=pool_arn)

    def _no_web_acl():
        return w.get_web_acl_for_resource(ResourceArn=pool_arn).get("WebACL") is None

    assert _poll_until(_no_web_acl), "GetWebACLForResource still returned a WebACL after a valid DisassociateWebACL"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
