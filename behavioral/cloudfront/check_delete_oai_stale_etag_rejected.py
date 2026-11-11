"""delete_oai_stale_etag_rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete_oai_stale_etag_rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteCloudFrontOriginAccessIdentity with a superseded ETag is refused with PreconditionFailed
    and leaves the OAI readable; the delete with the current ETag succeeds, after which a read and an
    update both return NoSuchCloudFrontOriginAccessIdentity."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-staleetag-")
    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "v1"}
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    stale_etag = created["ETag"]
    ctx.on_cleanup(lambda: _cleanup(ctx, oai_id))

    # mutate the resource so the ETag we hold becomes stale
    cf.update_cloud_front_origin_access_identity(
        Id=oai_id,
        IfMatch=stale_etag,
        CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "v2"},
    )

    # deleting with the stale ETag must fail, distinct from a plain not-found boundary
    code, message = _error(lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=stale_etag))
    assert code == "PreconditionFailed", f"expected PreconditionFailed for a stale-but-well-formed ETag, got {code}"
    assert message == "The request failed because it didn't meet the preconditions in one or more request-header fields.", f"unexpected PreconditionFailed message: {message!r}"

    # effect absent: an independent read shows the rejected delete did not touch the OAI
    still_there = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    got_id = still_there["CloudFrontOriginAccessIdentity"]["Id"]
    assert got_id == oai_id, f"expected the OAI {oai_id} to still exist, got {got_id}"
    current_etag = still_there["ETag"]

    # positive control / restore leg: the identical delete succeeds with the CURRENT ETag
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=current_etag)

    # gone: an independent read returns the specific not-found code
    gone_code, gone_message = _error(lambda: cf.get_cloud_front_origin_access_identity(Id=oai_id))
    assert gone_code == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected NoSuchCloudFrontOriginAccessIdentity, got {gone_code}"
    )
    assert gone_message == "The specified CloudFront origin access identity does not exist.", f"unexpected not-found message: {gone_message!r}"

    # unusable: a mutation on the deleted id also fails with the same not-found code
    mutate_code, mutate_message = _error(
        lambda: cf.update_cloud_front_origin_access_identity(
            Id=oai_id,
            IfMatch=current_etag,
            CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "v3"},
        )
    )
    assert mutate_code == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected NoSuchCloudFrontOriginAccessIdentity on a mutation of a deleted OAI, got {mutate_code}"
    )
    assert mutate_message == "The specified CloudFront origin access identity does not exist.", f"unexpected not-found message on update: {mutate_message!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _cleanup(ctx, oai_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cur = cf.get_cloud_front_origin_access_identity(Id=oai_id)
        cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=cur["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchCloudFrontOriginAccessIdentity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
