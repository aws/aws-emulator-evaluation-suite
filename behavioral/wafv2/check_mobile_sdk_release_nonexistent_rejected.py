"""mobile-sdk-release-nonexistent-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mobile-sdk-release-nonexistent-rejected"
GROUP = 'mobile-sdk'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"
_NOT_AUTHORIZED = "This account is not authorized to use Mobile-SDK"

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
    """Return (Code, Message) of the first NON-transient failure. Transient WAFv2 codes are
    retried rather than reported, so an assertion about a semantic error is never polluted by
    throttling or propagation delay. An unexpected SUCCESS raises, so an emulator accepting
    what AWS refuses never reads as a mere code mismatch."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            code, message = "", ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
                message = resp.get("Error", {}).get("Message", "")
            if code and code not in _TRANSIENT_CODES:
                return code, message
            if not code:
                raise
            if attempt == attempts - 1:
                return code, message
            time.sleep(delay)
            continue
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
    raise AssertionError("unreachable")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListWebACLs answers normally while ListMobileSdkReleases and GetMobileSdkRelease for a
    never-published version both fail with WAFInvalidOperationException and the exact not-authorized
    message: the access gate applies before the version lookup.
    """
    w = ctx.client("wafv2")

    # Positive control: the account/credentials are otherwise healthy for wafv2,
    # unrelated to mobile-SDK enrollment, so the refusals below are attributable
    # to the entitlement gate specifically.
    control = _retry_transient(lambda: w.list_web_acls(Scope=SCOPE))
    assert "WebACLs" in control, (
        f"positive control ListWebACLs did not return a normal response: {control!r}"
    )

    list_code, list_message = _error_stable(lambda: w.list_mobile_sdk_releases(Platform="IOS"))
    assert list_code == "WAFInvalidOperationException", (
        f"expected ListMobileSdkReleases to reject with the entitlement-gate code "
        f"WAFInvalidOperationException, got {list_code!r}"
    )
    assert list_message == _NOT_AUTHORIZED, list_message

    get_code, get_message = _error_stable(
        lambda: w.get_mobile_sdk_release(Platform="IOS", ReleaseVersion="0.0.0-nope")
    )
    assert get_code == "WAFInvalidOperationException", (
        f"expected GetMobileSdkRelease for a never-published version to reject "
        f"with the same entitlement-gate code WAFInvalidOperationException (the "
        f"gate must short-circuit before the not-found check runs), got {get_code!r}"
    )
    assert get_message == _NOT_AUTHORIZED, get_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
