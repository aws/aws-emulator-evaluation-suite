"""cloudfront-oai-delete-stale-etag-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudfront-oai-delete-stale-etag-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCloudFrontOriginAccessIdentity with a stale If-Match ETag is rejected with
    PreconditionFailed and the OAI is NOT deleted; the same delete succeeds once the caller
    supplies the CURRENT ETag (positive control)."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-oai-stale-cr-")

    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "stale-etag-test"}
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    stale_etag = created["ETag"]

    def _cleanup() -> None:
        try:
            e = cf.get_cloud_front_origin_access_identity(Id=oai_id)["ETag"]
            cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=e)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCloudFrontOriginAccessIdentity":
                raise

    ctx.on_cleanup(_cleanup)

    # Rotate the ETag by mutating the OAI, so `stale_etag` no longer matches the live version.
    cf.update_cloud_front_origin_access_identity(
        Id=oai_id,
        IfMatch=stale_etag,
        CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "rotated"},
    )

    code, message = _error(
        lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=stale_etag)
    )
    assert code == "PreconditionFailed", f"expected 412 PreconditionFailed, got {code!r}"
    expected = "The request failed because it didn't meet the preconditions in one or more request-header fields."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The forbidden effect did not happen: the OAI still exists.
    still_there = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    got_id = still_there["CloudFrontOriginAccessIdentity"]["Id"]
    assert got_id == oai_id, f"expected OAI {oai_id} to still exist after the rejected delete, got {got_id!r}"

    # Positive control: the same delete succeeds with the CURRENT ETag.
    current_etag = still_there["ETag"]
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=current_etag)

    code2, message2 = _error(lambda: cf.get_cloud_front_origin_access_identity(Id=oai_id))
    assert code2 == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected the real delete to make the OAI unreadable with NoSuchCloudFrontOriginAccessIdentity, got {code2!r}"
    )
    expected = "The specified CloudFront origin access identity does not exist."
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"

    # A delete's effect must also make the id unusable, not merely unreadable: a mutation on the
    # dead id must fail the same way an independent read does.
    code3, message3 = _error(
        lambda: cf.update_cloud_front_origin_access_identity(
            Id=oai_id,
            IfMatch=current_etag,
            CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "post-delete"},
        )
    )
    assert code3 == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected an update on the deleted OAI {oai_id} to fail with NoSuchCloudFrontOriginAccessIdentity, got {code3!r}"
    )
    expected = "The specified CloudFront origin access identity does not exist."
    assert message3 == expected, f"expected message {expected!r}, got {message3!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
