"""cloudfront-oai-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudfront-oai-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OAI transitions create->get->config-get->update->delete->404 correctly, with ETag
    rotating on each mutation and the CallerReference remaining immutable."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-oai-cr-")

    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": caller_ref,
            "Comment": "initial-comment",
        }
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    etag0 = created["ETag"]
    create_comment = created["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["Comment"]
    assert create_comment == "initial-comment", f"expected Comment 'initial-comment' on create, got {create_comment!r}"
    create_canonical_id = created["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"]

    def _cleanup() -> None:
        try:
            e = cf.get_cloud_front_origin_access_identity(Id=oai_id)["ETag"]
            cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=e)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchCloudFrontOriginAccessIdentity":
                raise

    ctx.on_cleanup(_cleanup)

    got = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    assert got["ETag"] == etag0, f"expected ETag {etag0!r} unchanged by a read, got {got['ETag']!r}"
    got_caller_ref = got["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["CallerReference"]
    assert got_caller_ref == caller_ref, f"expected CallerReference {caller_ref!r}, got {got_caller_ref!r}"
    s3_canonical_id = got["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"]
    assert len(s3_canonical_id) > 0, "S3CanonicalUserId must be populated on the independent get"
    assert s3_canonical_id == create_canonical_id, (
        f"S3CanonicalUserId must be stable across calls: create returned {create_canonical_id!r}, "
        f"get returned {s3_canonical_id!r}"
    )

    got_cfg = cf.get_cloud_front_origin_access_identity_config(Id=oai_id)
    assert got_cfg["ETag"] == etag0, f"expected config ETag {etag0!r}, got {got_cfg['ETag']!r}"
    cfg_comment = got_cfg["CloudFrontOriginAccessIdentityConfig"]["Comment"]
    assert cfg_comment == "initial-comment", f"expected config Comment 'initial-comment', got {cfg_comment!r}"

    updated = cf.update_cloud_front_origin_access_identity(
        Id=oai_id,
        IfMatch=etag0,
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": caller_ref,
            "Comment": "updated-comment",
        },
    )
    etag1 = updated["ETag"]
    assert etag1 != etag0, "ETag must rotate after a mutation"
    updated_comment = updated["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["Comment"]
    assert updated_comment == "updated-comment", f"expected Comment 'updated-comment' after update, got {updated_comment!r}"
    # CallerReference is immutable and must survive the update unchanged.
    updated_caller_ref = updated["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"][
        "CallerReference"
    ]
    assert updated_caller_ref == caller_ref, (
        f"CallerReference must remain immutable across an update: expected {caller_ref!r}, got {updated_caller_ref!r}"
    )

    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag1)

    def _error_code(fn) -> tuple[str, str]:
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError("expected ClientError on a deleted CloudFrontOriginAccessIdentity, call succeeded")

    missing = "The specified CloudFront origin access identity does not exist."
    code, message = _error_code(lambda: cf.get_cloud_front_origin_access_identity(Id=oai_id))
    assert code == "NoSuchCloudFrontOriginAccessIdentity", f"expected 404 NoSuch... on get after delete, got {code!r}"
    assert message == missing, f"GetCloudFrontOriginAccessIdentity message: {message!r}"

    # A mutation on the dead id must also fail with the same not-found code, not just a read.
    redelete_code, message = _error_code(lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag1))
    assert redelete_code == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected re-delete of a gone OAI to 404 NoSuch..., got {redelete_code!r}"
    )
    assert message == missing, f"DeleteCloudFrontOriginAccessIdentity message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
