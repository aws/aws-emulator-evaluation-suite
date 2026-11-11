"""mobile-sdk-release-lifecycle."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mobile-sdk-release-lifecycle"
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

def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises, so
    an emulator accepting what AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With Mobile SDK access, GetMobileSdkRelease resolves a listed version and its release URL is
    returned; without it, ListMobileSdkReleases, GetMobileSdkRelease and GenerateMobileSdkReleaseUrl
    all fail with WAFInvalidOperationException and the exact not-authorized message.
    """
    w = ctx.client("wafv2")

    _retry_transient(lambda: w.list_web_acls(Scope=SCOPE))

    try:
        listed = _retry_transient(lambda: w.list_mobile_sdk_releases(Platform="IOS"))
    except ClientError as exc:
        resp = exc.response.get("Error", {})
        code = resp.get("Code", "")
        assert code == "WAFInvalidOperationException", (
            f"expected ListMobileSdkReleases to reject with WAFInvalidOperationException "
            f"once denied, got {code!r}: {exc}"
        )
        message = resp.get("Message", "")
        assert message == _NOT_AUTHORIZED, message

        code_get, message_get = _error(
            lambda: w.get_mobile_sdk_release(Platform="IOS", ReleaseVersion="1.0.0")
        )
        assert code_get == "WAFInvalidOperationException", code_get
        assert message_get == _NOT_AUTHORIZED, message_get

        code_url, message_url = _error(
            lambda: w.generate_mobile_sdk_release_url(Platform="IOS", ReleaseVersion="1.0.0")
        )
        assert code_url == "WAFInvalidOperationException", code_url
        assert message_url == _NOT_AUTHORIZED, message_url
        return

    releases = listed.get("ReleaseSummaries", [])
    if not releases:
        raise AssertionError("no IOS mobile SDK releases published in this region")

    version = releases[0]["ReleaseVersion"]
    got = w.get_mobile_sdk_release(Platform="IOS", ReleaseVersion=version)
    got_version = got["MobileSdkRelease"]["ReleaseVersion"]
    assert got_version == version, f"expected GetMobileSdkRelease to resolve {version!r}, got {got_version!r}"

    url = w.generate_mobile_sdk_release_url(Platform="IOS", ReleaseVersion=version)
    assert url["Url"].startswith("http"), url

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
