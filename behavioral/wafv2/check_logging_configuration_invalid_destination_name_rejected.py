"""logging-configuration-invalid-destination-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "logging-configuration-invalid-destination-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"
_NOT_FOUND = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

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

_STABLE_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (Code, Message) of the first non-transient failure; transient codes are retried.
    An unexpected success raises, so acceptance never reads as a code mismatch."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            code, message = "", ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
                message = resp.get("Error", {}).get("Message", "")
            if code and code not in _STABLE_TRANSIENT_CODES:
                return code, message
            if not code:
                raise
            if attempt == attempts - 1:
                return code, message
            time.sleep(delay)
            continue
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
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

def _create_log_group(ctx, prefix, wildcard=True):
    """Create a CloudWatch Logs log group (registered for teardown); return its ARN.
    WAFv2 rejects a valid-looking destination ARN that still carries the ":*" the
    logs client's own ARN convention appends, so a real destination must have it
    stripped (`wildcard=False`)."""
    logs = ctx.client("logs")
    lg_name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=lg_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=lg_name))
    account = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{lg_name}"
    return f"{arn}:*" if wildcard else arn

def _delete_logging_config_best_effort(w, resource_arn):
    try:
        w.delete_logging_configuration(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLoggingConfiguration rejects a log group lacking the 'aws-waf-logs-' prefix with
    WAFInvalidParameterException and leaves the WebACL unconfigured, while a correctly
    prefixed destination on the same call shape is accepted (positive control)."""
    w = ctx.client("wafv2")
    summary = _create_web_acl(ctx, w)
    resource_arn = summary["ARN"]
    ctx.on_cleanup(lambda: _delete_logging_config_best_effort(w, resource_arn))

    good_log_arn = _create_log_group(ctx, "aws-waf-logs-", wildcard=False)
    _retry_transient(
        lambda: w.put_logging_configuration(
            LoggingConfiguration={
                "ResourceArn": resource_arn,
                "LogDestinationConfigs": [good_log_arn],
            }
        )
    )
    got = w.get_logging_configuration(ResourceArn=resource_arn)
    assert got["LoggingConfiguration"]["LogDestinationConfigs"] == [good_log_arn], got
    _retry_transient(lambda: w.delete_logging_configuration(ResourceArn=resource_arn))

    bad_log_arn = _create_log_group(ctx, "not-prefixed-", wildcard=False)
    code, message = _error_stable(
        lambda: w.put_logging_configuration(
            LoggingConfiguration={
                "ResourceArn": resource_arn,
                "LogDestinationConfigs": [bad_log_arn],
            }
        )
    )
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: The ARN isn't valid. A valid ARN begins with arn: and includes other "
        "information separated by colons or slashes., field: LOG_DESTINATION, "
        f"parameter: {bad_log_arn}"
    ), message

    after_rejection, after_message = _error_stable(
        lambda: w.get_logging_configuration(ResourceArn=resource_arn)
    )
    assert after_rejection == "WAFNonexistentItemException", after_rejection
    assert after_message == _NOT_FOUND, after_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
