"""tagging-lifecycle-tag-list-untag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tagging-lifecycle-tag-list-untag"
GROUP = 'tagging'
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


_NOT_FOUND_MESSAGE = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource upserts tags visible via ListTagsForResource; UntagResource
    removes only the named keys, leaving the rest intact."""
    w = ctx.client("wafv2")
    ipset = _create_ipset(ctx, w)
    _retry_transient(
        lambda: w.tag_resource(
            ResourceARN=ipset["ARN"],
            Tags=[
                {"Key": "env", "Value": "test"},
                {"Key": "owner", "Value": "fidelity-suite"},
            ],
        )
    )

    got = _retry_transient(
        lambda: w.list_tags_for_resource(ResourceARN=ipset["ARN"])
    )
    tag_map = {t["Key"]: t["Value"] for t in got["TagInfoForResource"]["TagList"]}
    assert tag_map == {"env": "test", "owner": "fidelity-suite"}, tag_map

    _retry_transient(
        lambda: w.untag_resource(ResourceARN=ipset["ARN"], TagKeys=["env"])
    )

    got2 = _retry_transient(
        lambda: w.list_tags_for_resource(ResourceARN=ipset["ARN"])
    )
    tag_map2 = {t["Key"]: t["Value"] for t in got2["TagInfoForResource"]["TagList"]}
    assert tag_map2 == {"owner": "fidelity-suite"}, tag_map2

    # Delete the IPSet in-check (rather than only in cleanup) so the delete is
    # itself an assertable event: an independent read must report the
    # specific not-found code, and a mutation against the dead id must also fail.
    lock_token = _retry_transient(
        lambda: w.get_ip_set(Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"])
    )["LockToken"]
    _retry_transient(
        lambda: w.delete_ip_set(
            Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"], LockToken=lock_token
        )
    )

    read_code, read_message = _error_stable(
        lambda: w.get_ip_set(Name=ipset["Name"], Scope=SCOPE, Id=ipset["Id"])
    )
    assert read_code == "WAFNonexistentItemException", read_code
    assert read_message == _NOT_FOUND_MESSAGE, read_message

    tag_code, tag_message = _error_stable(
        lambda: w.tag_resource(
            ResourceARN=ipset["ARN"], Tags=[{"Key": "post-delete", "Value": "x"}]
        )
    )
    assert tag_code == "WAFNonexistentItemException", tag_code
    assert tag_message == _NOT_FOUND_MESSAGE, tag_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
