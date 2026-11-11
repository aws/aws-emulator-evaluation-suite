"""loggingconfiguration-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "loggingconfiguration-lifecycle"
GROUP = 'logging'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFNonexistentItemException's message for a web ACL with no logging configuration.
NONEXISTENT_MESSAGE = (
    "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
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

def _delete_logging_if_present(w, arn):
    """Teardown: delete arn's logging configuration unless the check already deleted it."""
    try:
        w.delete_logging_configuration(ResourceArn=arn)
    except Exception as exc:  # noqa: BLE001 - inspect error code
        resp = getattr(exc, "response", None)
        code = resp.get("Error", {}).get("Code", "") if isinstance(resp, dict) else ""
        if code != "WAFNonexistentItemException":
            raise


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

def _create_webacl(ctx, w, name=None, rules=None, scope=SCOPE, default_allow=True):
    """Create a WebACL (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-acl-")
    summary = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction={"Allow": {}} if default_allow else {"Block": {}},
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")[:128]),
            Tags=[{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, summary["Id"]))
    return summary


def _account_id(ctx) -> str:
    """The caller's account id, from the target."""
    return ctx.account


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLoggingConfiguration: UNCONFIGURED -> CONFIGURED (visible via Get
    and ListLoggingConfigurations) -> DeleteLoggingConfiguration ->
    UNCONFIGURED (Get now WAFNonexistentItemException)."""
    w = ctx.client("wafv2")
    webacl = _create_webacl(ctx, w)
    # WAF validates the destination: a real log group in the same account+region
    # whose name starts with "aws-waf-logs-", ARN without a trailing ":*".
    logs = ctx.client("logs")
    lg_name = "aws-waf-logs-" + ctx.unique_name("behav-")
    logs.create_log_group(
        logGroupName=lg_name,
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=lg_name))
    account_id = _account_id(ctx)
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{lg_name}"

    code_before, msg_before = _error_stable(
        lambda: w.get_logging_configuration(ResourceArn=webacl["ARN"])
    )
    assert code_before == "WAFNonexistentItemException", code_before
    assert msg_before == NONEXISTENT_MESSAGE, msg_before

    _retry_transient(
        lambda: w.put_logging_configuration(
            LoggingConfiguration={
                "ResourceArn": webacl["ARN"],
                "LogDestinationConfigs": [log_group_arn],
            }
        )
    )
    ctx.on_cleanup(lambda: _delete_logging_if_present(w, webacl["ARN"]))

    got = w.get_logging_configuration(ResourceArn=webacl["ARN"])
    got_destinations = got["LoggingConfiguration"]["LogDestinationConfigs"]
    assert got_destinations == [log_group_arn], (
        f"expected LogDestinationConfigs == [{log_group_arn!r}], got {got_destinations!r}"
    )

    listed = _list_all(w.list_logging_configurations, "LoggingConfigurations")
    arns = [lc["ResourceArn"] for lc in listed]
    assert webacl["ARN"] in arns, (
        f"expected {webacl['ARN']!r} in ListLoggingConfigurations, got {arns!r}"
    )

    _retry_transient(
        lambda: w.delete_logging_configuration(ResourceArn=webacl["ARN"])
    )

    code_after, msg_after = _error_stable(
        lambda: w.get_logging_configuration(ResourceArn=webacl["ARN"])
    )
    assert code_after == "WAFNonexistentItemException", code_after
    assert msg_after == NONEXISTENT_MESSAGE, msg_after

    double_delete_code, double_delete_msg = _error_stable(
        lambda: w.delete_logging_configuration(ResourceArn=webacl["ARN"])
    )
    assert double_delete_code == "WAFNonexistentItemException", (
        f"expected a second delete on an already-deleted logging configuration "
        f"to raise WAFNonexistentItemException, got {double_delete_code!r}"
    )
    assert double_delete_msg == NONEXISTENT_MESSAGE, double_delete_msg

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
