"""op-contract-get-cloudfront-origin-access-identity-config."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-cloudfront-origin-access-identity-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCloudFrontOriginAccessIdentityConfig round-trips CallerReference/Comment, 404s on unknown Id."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-oaicfg-")
    comment = "sim2real behavioral test OAI config"
    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": comment}
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]

    def _cleanup() -> None:
        try:
            cur = cf.get_cloud_front_origin_access_identity(Id=oai_id)
            cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCloudFrontOriginAccessIdentity":
                raise

    ctx.on_cleanup(_cleanup)

    # success-path contract
    got = cf.get_cloud_front_origin_access_identity_config(Id=oai_id)
    assert got["CloudFrontOriginAccessIdentityConfig"]["CallerReference"] == caller_ref
    assert got["CloudFrontOriginAccessIdentityConfig"]["Comment"] == comment
    assert "ETag" in got

    # distinct error boundary: unknown Id
    error = _client_error(lambda: cf.get_cloud_front_origin_access_identity_config(Id="E0000000000001"))
    code = error["Code"]
    assert code == "NoSuchCloudFrontOriginAccessIdentity", f"unexpected code {code}"
    not_found_message = "The specified CloudFront origin access identity does not exist."
    assert error.get("Message") == not_found_message, (
        f"expected message {not_found_message!r}, got {error.get('Message')!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"real AWS rejects GetCloudFrontOriginAccessIdentityConfig(Id=<unknown>), but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
