"""web-acl-challenge-immunity-time-below-service-minimum-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "web-acl-challenge-immunity-time-below-service-minimum-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav-waf-acl-immunity"},
]

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

# TimeWindowSecond is modeled range min 60 / max 259200, so botocore lets all three of
# these through to the service (and botocore validates only `min`, never `max`).
_CHALLENGE_MIN = 300     # documented service minimum for the Challenge action
_CAPTCHA_OK = 60         # legal for CAPTCHA: proves 60 is not rejected per se
_TOO_LOW = 60            # model-legal, service-illegal for Challenge
_JUST_TOO_LOW = 299      # one BELOW the service minimum: pins the bound at exactly 300
_TOO_HIGH = 259201       # one past the modeled max; not checked client-side

# The two ends of the field are enforced by different validators: below the Challenge minimum
# WAF's semantic check reports Field/Reason/Parameter; above the modeled maximum the generic
# range check reports "N validation errors detected" against the lowerCamel member path.
_LOW_CODE = "WAFInvalidParameterException"
_LOW_REASON = "The parameter value is out of bounds."
_LOW_FIELD = "CHALLENGE_CONFIG"
_HIGH_CODE = "ValidationException"
_HIGH_MEMBER_PATH = "challengeConfig.immunityTimeProperty.immunityTime"
_MODELED_MAX = 259200


def _challenge_rule():
    """A rule whose action is Challenge, so the web ACL's ChallengeConfig is in effect."""
    return {
        "Name": "challenge-bots",
        "Priority": 0,
        "Statement": {"ByteMatchStatement": {
            "SearchString": b"/checkout",
            "FieldToMatch": {"UriPath": {}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
            "PositionalConstraint": "STARTS_WITH",
        }},
        "Action": {"Challenge": {}},
        "VisibilityConfig": _visibility_config("challengebots"),
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Challenge ImmunityTime 60 and 299 are refused (minimum 300, though the model allows 60 and
    CAPTCHA accepts it) and 259201 fails the generic range check, each leaving the ACL unchanged.

    Reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_ImmunityTimeProperty.html
    """
    w = ctx.client("wafv2")

    # ---- setup: a legal configuration. 300 for Challenge, 60 for CAPTCHA. The CAPTCHA
    # value being accepted is what proves 60 is not rejected as a number.
    acl_name = ctx.unique_name("sim2real-behav-waf-acl-immunity-")[:128]
    acl = _retry_transient(lambda: w.create_web_acl(
        Name=acl_name, Scope=SCOPE, DefaultAction={"Allow": {}},
        VisibilityConfig=_visibility_config("immunitymetric"),
        Rules=[_challenge_rule()],
        CaptchaConfig={"ImmunityTimeProperty": {"ImmunityTime": _CAPTCHA_OK}},
        ChallengeConfig={"ImmunityTimeProperty": {"ImmunityTime": _CHALLENGE_MIN}},
        Tags=_TAGS_KV,
    ))["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", acl_name, SCOPE, acl["Id"]))

    got = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    body = got["WebACL"]
    assert body["ChallengeConfig"]["ImmunityTimeProperty"]["ImmunityTime"] == _CHALLENGE_MIN, \
        body.get("ChallengeConfig")
    assert body["CaptchaConfig"]["ImmunityTimeProperty"]["ImmunityTime"] == _CAPTCHA_OK, (
        f"CaptchaConfig ImmunityTime={_CAPTCHA_OK} is legal (the 300 minimum applies only "
        f"to Challenge) but did not round-trip: {body.get('CaptchaConfig')}"
    )
    token = got["LockToken"]

    def _update(challenge_immunity, lock):
        return w.update_web_acl(
            Name=acl_name, Scope=SCOPE, Id=acl["Id"], LockToken=lock,
            DefaultAction={"Allow": {}},
            VisibilityConfig=_visibility_config("immunitymetric"),
            Rules=[_challenge_rule()],
            CaptchaConfig={"ImmunityTimeProperty": {"ImmunityTime": _CAPTCHA_OK}},
            ChallengeConfig={"ImmunityTimeProperty": {"ImmunityTime": challenge_immunity}},
        )

    # ---- break exactly one thing: Challenge immunity below the service minimum. Twice, at
    # 60 (the model's own minimum) and at 299 (one below the service minimum) -- the second
    # value is what pins the bound at exactly 300 rather than merely "somewhere above 60",
    # since 300 was accepted at create above.
    after = got
    for low in (_TOO_LOW, _JUST_TOO_LOW):
        code, resp = _error_code(lambda v=low: _update(v, token))
        assert code is not None, (
            f"UpdateWebACL accepted ChallengeConfig.ImmunityTime={low}; the documented "
            f"minimum for the Challenge action is {_CHALLENGE_MIN} seconds"
        )
        assert code == _LOW_CODE, (
            f"expected {_LOW_CODE} for a below-minimum Challenge immunity time {low}, got "
            f"{code}: {resp.get('Error')}"
        )
        assert resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400, resp.get(
            "ResponseMetadata", {}).get("HTTPStatusCode")
        # The service's own validator reports which config block was out of bounds, why, and
        # the offending value -- as a STRING, even though the field is an integer.
        assert resp.get("Field") == _LOW_FIELD, (
            f"the refusal must name Field {_LOW_FIELD} (not the immunity-time member), got "
            f"{resp.get('Field')!r}"
        )
        assert resp.get("Reason") == _LOW_REASON, f"unexpected Reason: {resp.get('Reason')!r}"
        assert resp.get("Parameter") == str(low), (
            f"the refusal must echo the offending value as a string, got "
            f"{resp.get('Parameter')!r} for {low}"
        )
        assert resp["Error"]["Message"] == (
            f"Error reason: {_LOW_REASON}, field: {_LOW_FIELD}, parameter: {low}"
        ), f"unexpected message for {low}: {resp['Error']['Message']!r}"

        # ---- the effect is absent, after each refusal: the stored immunity time is
        # untouched and the write did not happen (the LockToken did not rotate).
        after = _retry_transient(
            lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"])
        )
        assert after["WebACL"]["ChallengeConfig"]["ImmunityTimeProperty"]["ImmunityTime"] \
            == _CHALLENGE_MIN, (
            f"the refused update for {low} still lowered the stored Challenge immunity "
            f"time: {after['WebACL']['ChallengeConfig']}"
        )
        assert after["LockToken"] == token, (
            f"the refused UpdateWebACL for {low} rotated the LockToken, so it was treated "
            "as a successful write"
        )

    # ---- the other end of the same field is enforced by a DIFFERENT validator. `max` is
    # not validated by botocore, so an above-maximum value reaches the service, where the
    # generic range check answers ValidationException rather than WAF's semantic check.
    code_hi, resp_hi = _error_code(lambda: _update(_TOO_HIGH, token))
    assert code_hi is not None, (
        f"UpdateWebACL accepted ChallengeConfig.ImmunityTime={_TOO_HIGH}, one past the "
        f"modeled maximum of {_MODELED_MAX}"
    )
    assert code_hi == _HIGH_CODE, (
        f"expected {_HIGH_CODE} for an above-maximum immunity time, got "
        f"{code_hi}: {resp_hi.get('Error')}"
    )
    assert code_hi != _LOW_CODE, (
        "the two ends of ImmunityTime are enforced by different validators and must not "
        f"collapse into one error code: both reported {code_hi}"
    )
    assert resp_hi["Error"]["Message"] == (
        f"1 validation error detected: Value '{_TOO_HIGH}' at '{_HIGH_MEMBER_PATH}' failed "
        f"to satisfy constraint: Member must have value less than or equal to {_MODELED_MAX}"
    ), f"unexpected above-maximum diagnostic: {resp_hi['Error']['Message']!r}"
    # And it carries none of the WAF-shaped fields the low-end refusal did.
    assert not any(k in resp_hi for k in ("Field", "Reason", "Parameter")), (
        f"the framework range check reports no WAF Field/Reason/Parameter, got "
        f"{sorted(k for k in resp_hi if k != 'ResponseMetadata')}"
    )
    # Effect absent for this one too.
    after = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    assert after["WebACL"]["ChallengeConfig"]["ImmunityTimeProperty"]["ImmunityTime"] \
        == _CHALLENGE_MIN, after["WebACL"]["ChallengeConfig"]
    assert after["LockToken"] == token, (
        "the refused above-maximum UpdateWebACL rotated the LockToken"
    )

    # ---- the control still works: a legal value >= 300 updates successfully, so the two
    # refusals were about the bound and not about the request shape.
    ok = _retry_transient(lambda: _update(_CHALLENGE_MIN + 60, after["LockToken"]))
    assert ok["NextLockToken"] != token, ok["NextLockToken"]
    control = _retry_transient(lambda: w.get_web_acl(Name=acl_name, Scope=SCOPE, Id=acl["Id"]))
    assert control["WebACL"]["ChallengeConfig"]["ImmunityTimeProperty"]["ImmunityTime"] \
        == _CHALLENGE_MIN + 60, control["WebACL"]["ChallengeConfig"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
