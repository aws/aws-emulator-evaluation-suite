"""web-acl-custom-response-body-key-missing-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "web-acl-custom-response-body-key-missing-rejected"
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


def _error_code(fn):
    """Run fn, expecting failure; return (code, response). An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - the error IS the assertion target
        resp = getattr(exc, "response", None)
        if not isinstance(resp, dict):
            raise
        return resp.get("Error", {}).get("Code", ""), resp
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _delete_locked(w, kind, name, scope, id_):
    """Delete a WAFv2 resource, ALWAYS re-fetching its LockToken inside this call.

    A LockToken captured at create time is invalidated by every intervening update, and
    DeleteWebACL with a stale token fails with WAFOptimisticLockException -- which means
    the web ACL survives and keeps billing.
    """
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    cur = _retry_transient(lambda: getter(Name=name, Scope=scope, Id=id_))
    token = cur["LockToken"]
    _retry_transient(
        lambda: deleter(Name=name, Scope=scope, Id=id_, LockToken=token),
        codes=_TRANSIENT_CODES | {"WAFAssociatedItemException"},
    )

_BODY_KEY = "blocked-html"
_MISSING_KEY = "undefined-body-key"
_BODIES = {
    _BODY_KEY: {
        "ContentType": "TEXT_HTML",
        "Content": "<html><body>Request blocked by policy.</body></html>",
    }
}


def _dangling_key_message(key):
    """WAF's refusal for a CustomResponseBodyKey that names no CustomResponseBodies entry."""
    return (
        "Error reason: AWS WAF couldn't find a resource that a parameter references., "
        f"field: CUSTOM_RESPONSE, parameter: {key}"
    )


def _block_rule(body_key):
    """A Block rule whose CustomResponse references a body by key."""
    return {
        "Name": "block-admin",
        "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "SearchString": b"/admin",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "STARTS_WITH",
        }},
        "Action": {"Block": {"CustomResponse": {
            "ResponseCode": 403,
            "CustomResponseBodyKey": body_key,
            "ResponseHeaders": [{"Name": "x-blocked-by", "Value": "waf-probe"}],
        }}},
        "VisibilityConfig": _visibility_config("blockadmin"),
    }


def _count_rule():
    """A Count rule with CustomRequestHandling, the request-side counterpart."""
    return {
        "Name": "tag-api",
        "Priority": 1,
        "Statement": {"ByteMatchStatement": {
            "SearchString": b"/api",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "STARTS_WITH",
        }},
        "Action": {"Count": {"CustomRequestHandling": {
            "InsertHeaders": [{"Name": "x-waf-probe-seen", "Value": "1"}]
        }}},
        "VisibilityConfig": _visibility_config("tagapi"),
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A web ACL's custom response, headers and body map round-trip; UpdateWebACL with a
    CustomResponseBodyKey not in CustomResponseBodies (or with the map dropped) fails with
    WAFInvalidParameterException, HTTP 400 and the exact message, leaving the web ACL unchanged.
    """
    w = ctx.client("wafv2")

    # ---- setup: a fully valid custom-response configuration.
    acl_name = ctx.unique_name("sim2real-behav-waf-acl-cresp-")[:128]
    acl = _retry_transient(lambda: w.create_web_acl(
        Name=acl_name, Scope=SCOPE, DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("customrespmetric"),
        CustomResponseBodies=_BODIES,
        Rules=[_block_rule(_BODY_KEY), _count_rule()],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", acl_name, SCOPE, acl["Id"]))

    got = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    body = got["WebACL"]
    # The whole custom-response document round-trips, key by key.
    assert body["CustomResponseBodies"] == _BODIES, body.get("CustomResponseBodies")
    block = body["Rules"][0]["Action"]["Block"]["CustomResponse"]
    assert block["CustomResponseBodyKey"] == _BODY_KEY, block
    assert block["ResponseCode"] == 403, block
    assert block["ResponseHeaders"] == [{"Name": "x-blocked-by", "Value": "waf-probe"}], block
    count = body["Rules"][1]["Action"]["Count"]["CustomRequestHandling"]
    assert count["InsertHeaders"] == [{"Name": "x-waf-probe-seen", "Value": "1"}], count
    token = got["LockToken"]

    def _update(body_key, lock, bodies=None):
        kwargs = {
            "Name": acl_name, "Scope": SCOPE, "Id": acl["Id"], "LockToken": lock,
            "DefaultAction": {"Allow": {}},
            "VisibilityConfig": _visibility_config("customrespmetric"),
            "Rules": [_block_rule(body_key), _count_rule()],
        }
        if bodies is not None:
            kwargs["CustomResponseBodies"] = bodies
        return w.update_web_acl(**kwargs)

    # ---- break exactly one thing: the referenced key is not in the map.
    code, resp = _error_code(lambda: _update(_MISSING_KEY, token, _BODIES))
    assert code is not None, (
        f"UpdateWebACL accepted CustomResponseBodyKey={_MISSING_KEY!r}, which is not a key "
        f"in CustomResponseBodies ({sorted(_BODIES)}); the dangling reference was not "
        f"validated"
    )
    assert code == "WAFInvalidParameterException", (
        f"expected WAFInvalidParameterException for a dangling CustomResponseBodyKey, got "
        f"{code}: {resp.get('Error')}"
    )
    assert resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400, resp.get(
        "ResponseMetadata", {}).get("HTTPStatusCode")
    assert resp["Error"]["Message"] == _dangling_key_message(_MISSING_KEY), resp["Error"]

    # ---- the effect is absent.
    after = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    still = after["WebACL"]["Rules"][0]["Action"]["Block"]["CustomResponse"]
    assert still["CustomResponseBodyKey"] == _BODY_KEY, (
        f"the refused update still rewrote the stored body key: {still}"
    )
    assert after["WebACL"]["CustomResponseBodies"] == _BODIES, \
        after["WebACL"].get("CustomResponseBodies")
    assert after["LockToken"] == token, (
        "the refused UpdateWebACL rotated the LockToken, so it was treated as a "
        "successful write"
    )

    # ---- the same dangling reference produced by DROPPING the map instead of renaming
    # the key: the rule still names a real-looking key, but the web ACL no longer defines
    # any bodies. UpdateWebACL is a full replace, so omitting CustomResponseBodies removes
    # them, and the reference must break.
    code2, resp2 = _error_code(lambda: _update(_BODY_KEY, token, None))
    assert code2 is not None, (
        "UpdateWebACL accepted a rule referencing CustomResponseBodyKey "
        f"{_BODY_KEY!r} while removing CustomResponseBodies entirely"
    )
    assert code2 == "WAFInvalidParameterException", (
        f"expected WAFInvalidParameterException when the body map is dropped out from "
        f"under a live reference, got {code2}: {resp2.get('Error')}"
    )
    assert resp2["Error"]["Message"] == _dangling_key_message(_BODY_KEY), resp2["Error"]

    # ---- the control still works: the resolvable key updates successfully.
    ok = _retry_transient(lambda: _update(_BODY_KEY, token, _BODIES))
    assert ok["NextLockToken"] != token, ok["NextLockToken"]
    control = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    assert control["WebACL"]["Rules"][0]["Action"]["Block"]["CustomResponse"][
        "CustomResponseBodyKey"] == _BODY_KEY, control["WebACL"]["Rules"][0]["Action"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
