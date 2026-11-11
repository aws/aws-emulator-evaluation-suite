"""generate-mobile-sdk-release-url-invalid-platform-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "generate-mobile-sdk-release-url-invalid-platform-rejected"
GROUP = "overly-permissive"
SERVICES = ["wafv2"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GenerateMobileSdkReleaseUrl rejects a malformed ReleaseVersion with ValidationException and the
    exact pattern message. On an account without Mobile SDK access, ListMobileSdkReleases and
    GenerateMobileSdkReleaseUrl both fail with WAFInvalidOperationException; otherwise the URL is https.
    """
    wafv2 = ctx.client("wafv2")

    code, message = _error(
        lambda: wafv2.generate_mobile_sdk_release_url(
            Platform="IOS", ReleaseVersion="not a valid version!!"
        )
    )
    # A malformed ReleaseVersion fails request validation (ValidationException), not the
    # WAFInvalidParameterException WAF uses for valid but unrecognized parameters.
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'not a valid version!!' at 'releaseVersion' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "^[\\w#:\\.\\-/]+$"
    ), message

    release_version, list_error = _find_a_release_version(wafv2)
    if release_version is None:
        # Without Mobile SDK access, ListMobileSdkReleases rejects both platforms with
        # WAFInvalidOperationException; GenerateMobileSdkReleaseUrl must be gated the same way.
        assert list_error == "WAFInvalidOperationException", (
            "expected ListMobileSdkReleases to reject with "
            f"WAFInvalidOperationException when no release is published, got {list_error!r}"
        )
        code_generate, _message = _error(
            lambda: wafv2.generate_mobile_sdk_release_url(
                Platform="IOS", ReleaseVersion="1.0.0"
            )
        )
        assert code_generate == "WAFInvalidOperationException", (
            "expected GenerateMobileSdkReleaseUrl to reject with the same "
            f"WAFInvalidOperationException as ListMobileSdkReleases, got {code_generate!r}"
        )
        return

    platform, version = release_version
    url_resp = wafv2.generate_mobile_sdk_release_url(
        Platform=platform, ReleaseVersion=version
    )
    assert url_resp["Url"].startswith("https://"), (
        f"expected an https:// download URL, got {url_resp.get('Url')!r}"
    )


def _find_a_release_version(wafv2):
    """Return ((platform, version), None) for the first published release found,
    or (None, last_error_code) if neither platform yields one."""
    last_error = None
    for platform in ("IOS", "ANDROID"):
        try:
            releases = wafv2.list_mobile_sdk_releases(Platform=platform).get(
                "ReleaseSummaries", []
            )
        except ClientError as e:
            last_error = e.response["Error"]["Code"]
            continue
        for release in releases:
            version = release.get("ReleaseVersion")
            if version:
                return (platform, version), None
    return None, last_error


def _error(fn: Callable[[], Any]):
    """Call fn(); return (code, message) of its botocore error. A call that succeeds
    raises AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
