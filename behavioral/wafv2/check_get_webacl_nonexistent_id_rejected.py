"""get-webacl-nonexistent-id-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-webacl-nonexistent-id-rejected"
GROUP = 'error-semantics'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFNonexistentItemException's message for a web ACL that does not exist.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0):
    """Retry WAFv2's transient control-plane errors (throttling / just-created
    entity not yet resolvable); re-raise anything else."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
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

def _delete_locked(w, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_web_acl requires the current token)."""
    try:
        lt = w.get_web_acl(Name=name, Scope=scope, Id=id_)["LockToken"]
        w.delete_web_acl(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWebACL returns a just-created WebACL's own Id, and fails with WAFNonexistentItemException and
    the exact not-found message for a well-formed but nonexistent Id.
    """
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-acl-missing-")

    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]
    real_id = created["Id"]
    ctx.on_cleanup(lambda: _delete_locked(w, name, SCOPE, real_id))

    control = w.get_web_acl(Name=name, Scope=SCOPE, Id=real_id)
    assert control["WebACL"]["Id"] == real_id, (
        f"positive control failed: expected GetWebACL to return Id {real_id!r}, "
        f"got {control['WebACL'].get('Id')!r}"
    )

    bogus_name = ctx.unique_name("sim2real-behav-waf-acl-missing-")
    code, message = _error_stable(
        lambda: w.get_web_acl(
            Name=bogus_name,
            Scope=SCOPE,
            Id="00000000-0000-0000-0000-000000000000",
        )
    )
    assert code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException for a well-formed but nonexistent "
        f"Id, got {code!r}"
    )
    assert message == NONEXISTENT_MESSAGE, message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
