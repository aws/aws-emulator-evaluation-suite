"""managed-rule-group-pinned-version-nonexistent-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "managed-rule-group-pinned-version-nonexistent-rejected"
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
    """Run fn, expecting failure; return (code, response). An unexpected SUCCESS raises, so
    an emulator accepting what AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - the error IS the assertion target
        resp = getattr(exc, "response", None)
        if not isinstance(resp, dict):
            raise
        return resp.get("Error", {}).get("Code", ""), resp
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _managed_rule(version=None, name="managed"):
    """A rule referencing the AWS core rule set, optionally pinned to a version."""
    stmt = {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}
    if version is not None:
        stmt["Version"] = version
    return {
        "Name": name,
        "Priority": 0,
        "Statement": {"ManagedRuleGroupStatement": stmt},
        "OverrideAction": {"None": {}},
        "VisibilityConfig": _visibility_config(name),
    }

# A version string that is syntactically well-formed (so it passes the model's pattern
# constraint and reaches the service) but cannot exist in the AWS catalog.
_BOGUS_VERSION = "Version_9.99"
_NOT_FOUND = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CheckCapacity and CreateWebACL refuse a managed rule group pinned to an unpublished Version with
    WAFNonexistentItemException, HTTP 400 and the exact not-found message; no web ACL is created, and
    the default Version yields the same capacity before and after.
    """
    w = ctx.client("wafv2")

    # ---- setup: establish the real default version, so the ONLY difference below is
    # the version string.
    versions = _retry_transient(lambda: w.list_available_managed_rule_group_versions(
        VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope=SCOPE, Limit=50
    ))
    default = versions["CurrentDefaultVersion"]
    listed = {v["Name"] for v in versions.get("Versions", [])}
    assert default in listed, (default, sorted(listed))
    assert _BOGUS_VERSION not in listed, (
        f"premise broken: {_BOGUS_VERSION} is a real published version"
    )

    # ---- control: the identical statement at the real version is accepted.
    good_capacity = _retry_transient(lambda: w.check_capacity(
        Scope=SCOPE, Rules=[_managed_rule(default)]
    ))["Capacity"]
    assert good_capacity > 0, good_capacity

    # ---- break exactly one thing: the pinned version.
    # _retry_transient nested INSIDE _error_code: _error_code captures any exception, so an
    # untreated ThrottlingException / WAFUnavailableEntityException / WAFInternalErrorException --
    # all of which WAFv2 routinely returns and which this file already lists as transient -- would
    # be mistaken for the refusal being asserted and fail the code comparison spuriously.
    # _retry_transient re-raises non-transient codes, so the real validation error still surfaces.
    code, resp = _error_code(lambda: _retry_transient(lambda: w.check_capacity(
        Scope=SCOPE, Rules=[_managed_rule(_BOGUS_VERSION)]
    )))
    assert code == "WAFNonexistentItemException", (
        f"expected a WAF validation error for a nonexistent managed rule group version, "
        f"got {code}: {resp.get('Error')}"
    )
    assert resp["Error"].get("Message") == _NOT_FOUND, resp["Error"]
    status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 400, f"expected HTTP 400, got {status}"

    # ---- and the same break on the mutating path must refuse to create the ACL.
    acl_name = ctx.unique_name("sim2real-behav-waf-acl-badver-")[:128]

    def _reap():
        """Delete the web ACL if it exists after all. LockToken is fetched INSIDE the
        lambda so it can never be stale."""
        try:
            found = [a for a in _list_all(w.list_web_acls, "WebACLs")
                     if a["Name"] == acl_name]
            for a in found:
                cur = w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=a["Id"])
                w.delete_web_acl(Name=acl_name, Scope=SCOPE, Id=a["Id"],
                                 LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_reap)

    code2, resp2 = _error_code(lambda: _retry_transient(lambda: w.create_web_acl(
        Name=acl_name, Scope=SCOPE, DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("badver"),
        Rules=[_managed_rule(_BOGUS_VERSION)],
    )))
    assert code2 == "WAFNonexistentItemException", (
        f"expected a WAF validation error, got {code2}: {resp2.get('Error')}"
    )
    assert resp2["Error"].get("Message") == _NOT_FOUND, resp2["Error"]

    # ---- the effect is absent: no web ACL by that name exists.
    names = {a["Name"] for a in _list_all(w.list_web_acls, "WebACLs")}
    assert acl_name not in names, (
        f"the refused CreateWebACL still created {acl_name} -- the rejection was not "
        f"atomic"
    )

    # ---- the control still works: the unbroken statement is still accepted, so the
    # refusal was about the version and not about the request as a whole.
    again = _retry_transient(lambda: w.check_capacity(
        Scope=SCOPE, Rules=[_managed_rule(default)]
    ))["Capacity"]
    assert again == good_capacity, (good_capacity, again)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
