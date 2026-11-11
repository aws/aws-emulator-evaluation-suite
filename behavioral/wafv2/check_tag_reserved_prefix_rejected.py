"""tag-reserved-prefix-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-reserved-prefix-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

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
    """Return (code, message) of the first NON-transient failure; an unexpected success
    raises. Transient WAFv2 codes are retried rather than reported, so an assertion about
    a semantic error is never polluted by throttling or propagation delay."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            err = resp.get("Error", {}) if isinstance(resp, dict) else {}
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message")
            time.sleep(delay)
            continue
        raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")
    raise AssertionError("unreachable: attempts must be positive")

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token). Already
    gone is clean; a reference still being released or a transient error is retried for 15 s."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    retryable = _TRANSIENT_CODES | {"WAFAssociatedItemException", "WAFOptimisticLockException"}
    deadline = time.monotonic() + 15.0
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            if code not in retryable or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _create_ipset(ctx, w, name=None, addresses=None, scope=SCOPE):
    """Create an IPSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-ips-")
    addresses = addresses if addresses is not None else ["10.0.0.0/8"]
    summary = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=addresses
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, scope, summary["Id"]))
    return summary

_RESERVED_TAG_MESSAGE = (
    "You tried to tag your resources with system tag keys. These tags have an aws: prefix "
    "and are reserved by AWS. Change your tag keys, and try again."
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with a reserved 'aws:' key prefix is rejected and leaves the tag absent,
    while a valid key on the same resource (the positive control) succeeds and is listed."""
    w = ctx.client("wafv2")
    ipset = _create_ipset(ctx, w)
    code, message = _error_stable(
        lambda: w.tag_resource(
            ResourceARN=ipset["ARN"], Tags=[{"Key": "aws:reserved", "Value": "nope"}]
        )
    )
    assert code == "WAFTagOperationException", code
    assert message == _RESERVED_TAG_MESSAGE, message

    rejected_tags = _retry_transient(
        lambda: w.list_tags_for_resource(ResourceARN=ipset["ARN"])
    )["TagInfoForResource"]["TagList"]
    assert all(t["Key"] != "aws:reserved" for t in rejected_tags), rejected_tags

    _retry_transient(
        lambda: w.tag_resource(
            ResourceARN=ipset["ARN"], Tags=[{"Key": "sim2real-team", "Value": "fidelity"}]
        )
    )
    accepted_tags = _retry_transient(
        lambda: w.list_tags_for_resource(ResourceARN=ipset["ARN"])
    )["TagInfoForResource"]["TagList"]
    matching = [t for t in accepted_tags if t["Key"] == "sim2real-team"]
    assert len(matching) == 1 and matching[0]["Value"] == "fidelity", accepted_tags

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
