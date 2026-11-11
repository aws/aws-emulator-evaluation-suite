"""get-webacl-for-resource-unsupported-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-webacl-for-resource-unsupported-arn-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (code, message) of the first non-transient failure of fn, retrying transient codes.

    A call that succeeds raises AssertionError: the caller expects a refusal.
    """
    for attempt in range(attempts):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            err = resp.get("Error", {}) if isinstance(resp, dict) else {}
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message", "")
            time.sleep(delay)
            continue
        raise AssertionError("expected the call to be refused, but it succeeded")
    raise AssertionError("unreachable: every attempt returns or raises")

def _retry_transient(fn, attempts=12, delay=6.0):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created entity not yet resolvable); re-raise anything else."""
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            code = resp.get("Error", {}).get("Code", "") if isinstance(resp, dict) else ""
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                raise
            time.sleep(delay)
    raise AssertionError("unreachable: every attempt returns or raises")

def _delete_user_pool_retrying(cognito, pool_id, attempts=6, delay=5.0):
    """Delete the user pool, retrying TooManyRequestsException.

    The per-account DeleteUserPool quota is low, so a single-shot delete can leak the pool.
    """
    for attempt in range(attempts):
        try:
            cognito.delete_user_pool(UserPoolId=pool_id)
            return
        except Exception as exc:  # noqa: BLE001
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code != "TooManyRequestsException" or attempt == attempts - 1:
                raise
            time.sleep(delay)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWebACLForResource rejects an S3 bucket ARN (not a WAF-protectable type) with
    WAFInvalidParameterException, while a Cognito user pool ARN succeeds as the positive control."""
    w = ctx.client("wafv2")
    cognito = ctx.client("cognito-idp")

    pool_name = ctx.unique_name("sim2real-behav-waf-pool-")
    pool = cognito.create_user_pool(
        PoolName=pool_name,
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]
    pool_arn = pool["Arn"]
    ctx.on_cleanup(lambda: _delete_user_pool_retrying(cognito, pool["Id"]))

    _retry_transient(lambda: w.get_web_acl_for_resource(ResourceArn=pool_arn))

    bad_resource = f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-waf-bucket-')}"
    code, message = _error_stable(lambda: w.get_web_acl_for_resource(ResourceArn=bad_resource))
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: The ARN isn't valid. A valid ARN begins with arn: and includes other "
        "information separated by colons or slashes., field: RESOURCE_ARN, "
        f"parameter: {bad_resource}"
    ), message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
