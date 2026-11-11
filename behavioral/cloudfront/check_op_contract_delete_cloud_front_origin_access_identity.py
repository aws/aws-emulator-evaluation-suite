"""op-contract-deleteCloudFrontOriginAccessIdentity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteCloudFrontOriginAccessIdentity"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCloudFrontOriginAccessIdentity: a stale IfMatch is rejected distinctly
    from a correct delete, which removes the OAI so Get reports NotFound."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-oai-")

    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real behavioral check",
        }
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    etag = created["ETag"]

    def _cleanup(oai_id=oai_id):
        try:
            fresh = cf.get_cloud_front_origin_access_identity(Id=oai_id)
            cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=fresh["ETag"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCloudFrontOriginAccessIdentity":
                raise

    ctx.on_cleanup(_cleanup)

    # error boundary: garbled IfMatch is rejected while the OAI still exists
    bad_code, bad_message = _error(
        lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch='"bogus-etag"')
    )
    assert bad_code == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion, got {bad_code}"
    assert bad_message == "The If-Match version is missing or not valid for the resource.", (
        f"expected the exact refusal message, got {bad_message!r}"
    )

    # success path
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag)
    gone_code, gone_message = _error(lambda: cf.get_cloud_front_origin_access_identity(Id=oai_id))
    assert gone_code == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected NoSuchCloudFrontOriginAccessIdentity, got {gone_code}"
    )
    assert gone_message == "The specified CloudFront origin access identity does not exist.", (
        f"expected the exact refusal message, got {gone_message!r}"
    )

    # the dead id is not just unreadable — a further mutation on it also fails
    redelete_code, redelete_message = _error(
        lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag)
    )
    assert redelete_code == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected a delete of an already-deleted OAI to report NoSuchCloudFrontOriginAccessIdentity, "
        f"got {redelete_code}"
    )
    assert redelete_message == "The specified CloudFront origin access identity does not exist.", (
        f"expected the exact refusal message, got {redelete_message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    because an emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
