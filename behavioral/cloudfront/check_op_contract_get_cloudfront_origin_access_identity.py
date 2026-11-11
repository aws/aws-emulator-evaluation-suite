"""op-contract-get-cloudfront-origin-access-identity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-cloudfront-origin-access-identity"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCloudFrontOriginAccessIdentity returns S3CanonicalUserId, and 404s on unknown Id."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-oai-")
    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real behavioral test OAI",
        }
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    create_etag = created["ETag"]
    create_s3_uid = created["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"]
    assert isinstance(create_s3_uid, str) and len(create_s3_uid) > 0, (
        f"S3CanonicalUserId must be populated on create, got {create_s3_uid!r}"
    )

    def _cleanup() -> None:
        try:
            cur = cf.get_cloud_front_origin_access_identity(Id=oai_id)
            cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=cur["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCloudFrontOriginAccessIdentity":
                raise

    ctx.on_cleanup(_cleanup)

    # success-path contract: independent read agrees with the target's own create-time state
    got = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    assert got["CloudFrontOriginAccessIdentity"]["Id"] == oai_id, (
        f"expected Id {oai_id}, got {got['CloudFrontOriginAccessIdentity']['Id']}"
    )
    s3_uid = got["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"]
    assert s3_uid == create_s3_uid, f"expected S3CanonicalUserId {create_s3_uid}, got {s3_uid}"
    assert got["ETag"] == create_etag, f"expected ETag {create_etag}, got {got.get('ETag')}"

    # distinct error boundary: unknown Id
    code, message = _error(lambda: cf.get_cloud_front_origin_access_identity(Id="E0000000000000"))
    assert code == "NoSuchCloudFrontOriginAccessIdentity", f"unexpected code {code}"
    not_found_message = "The specified CloudFront origin access identity does not exist."
    assert message == not_found_message, f"expected message {not_found_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
