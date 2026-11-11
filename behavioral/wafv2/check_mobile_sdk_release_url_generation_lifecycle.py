"""mobile-sdk-release-url-generation-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mobile-sdk-release-url-generation-lifecycle"
GROUP = "state-machine"
SERVICES = ["wafv2"]

_NOT_AUTHORIZED = "This account is not authorized to use Mobile-SDK"


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On an account not enrolled in Mobile SDK, ListMobileSdkReleases, GenerateMobileSdkReleaseUrl
    and GetMobileSdkRelease fail WAFInvalidOperationException (ListWebACLs is the control);
    when enrolled, a listed release yields an https URL and matching version and Timestamp."""
    wafv2 = ctx.client("wafv2")

    # Positive control: this account's WAFv2 credentials are otherwise healthy, so a
    # WAFInvalidOperationException below is specific to Mobile SDK entitlement, not a
    # blanket connectivity/permission failure that would make every call fail alike.
    positive_control = wafv2.list_web_acls(Scope="REGIONAL", Limit=1)
    assert "WebACLs" in positive_control, (
        f"expected ListWebACLs to succeed as a positive control, got {positive_control!r}"
    )

    release = None
    platform_used = None
    list_error = None
    list_message = None
    for platform in ("IOS", "ANDROID"):
        try:
            releases = wafv2.list_mobile_sdk_releases(Platform=platform).get("ReleaseSummaries", [])
        except ClientError as e:
            list_error = e.response["Error"]["Code"]
            list_message = e.response["Error"].get("Message")
            continue
        if releases:
            release = releases[0]
            platform_used = platform
            break

    if release is None:
        # Not authorized (or no releases published) for either platform.
        # Confirm this is the specific, stable gating error, and that it is
        # applied consistently across the whole mobile-sdk operation family.
        assert list_error == "WAFInvalidOperationException", (
            f"expected ListMobileSdkReleases to reject with "
            f"WAFInvalidOperationException, got {list_error!r}"
        )
        assert list_message == _NOT_AUTHORIZED, list_message

        code_generate, message_generate = _error(
            lambda: wafv2.generate_mobile_sdk_release_url(
                Platform="IOS", ReleaseVersion="1.0.0"
            )
        )
        assert code_generate == "WAFInvalidOperationException", (
            f"expected GenerateMobileSdkReleaseUrl to reject with the same "
            f"WAFInvalidOperationException as ListMobileSdkReleases, got {code_generate!r}"
        )
        assert message_generate == _NOT_AUTHORIZED, message_generate

        code_get, message_get = _error(
            lambda: wafv2.get_mobile_sdk_release(Platform="IOS", ReleaseVersion="1.0.0")
        )
        assert code_get == "WAFInvalidOperationException", (
            f"expected GetMobileSdkRelease to reject with the same "
            f"WAFInvalidOperationException as ListMobileSdkReleases, got {code_get!r}"
        )
        assert message_get == _NOT_AUTHORIZED, message_get
        return

    version = release["ReleaseVersion"]
    list_timestamp = release["Timestamp"]

    url_resp = wafv2.generate_mobile_sdk_release_url(Platform=platform_used, ReleaseVersion=version)
    url = url_resp["Url"]
    assert isinstance(url, str) and url.startswith("https://"), (
        f"expected a presigned https download URL, got {url!r}"
    )

    detail = wafv2.get_mobile_sdk_release(Platform=platform_used, ReleaseVersion=version)[
        "MobileSdkRelease"
    ]
    assert detail["ReleaseVersion"] == version, (
        f"GetMobileSdkRelease returned ReleaseVersion {detail['ReleaseVersion']!r}, "
        f"expected the version {version!r} generated against"
    )
    assert detail["Timestamp"] == list_timestamp, (
        f"GetMobileSdkRelease Timestamp {detail['Timestamp']!r} must match the "
        f"ListMobileSdkReleases summary {list_timestamp!r} for the same release"
    )



def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected success raises, so
    acceptance never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
