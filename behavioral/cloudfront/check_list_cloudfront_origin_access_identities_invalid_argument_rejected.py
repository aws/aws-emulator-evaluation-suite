"""list-cloudfront-origin-access-identities-invalid-argument-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-cloudfront-origin-access-identities-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListCloudFrontOriginAccessIdentities with a non-numeric MaxItems is refused with InvalidArgument
    and "MaxItems must be a non-zero positive integer.", while MaxItems "5" succeeds."""
    cf = ctx.client("cloudfront")

    code, message = _error_code_and_message(
        lambda: cf.list_cloud_front_origin_access_identities(MaxItems="not-a-number")
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "MaxItems must be a non-zero positive integer.", f"unexpected message {message!r}"

    control = cf.list_cloud_front_origin_access_identities(MaxItems="5")
    assert "CloudFrontOriginAccessIdentityList" in control, (
        f"expected a well-shaped response for the positive control, got {control!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
