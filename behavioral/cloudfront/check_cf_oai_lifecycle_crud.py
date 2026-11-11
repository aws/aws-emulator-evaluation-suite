"""cf-oai-lifecycle-crud."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "cf-oai-lifecycle-crud"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OAI supports create->get->update->delete with a real config round-trip and ETag bump."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-oai-")

    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real-behav initial",
        }
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    create_etag = created["ETag"]
    s3_canonical_id = created["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"]
    assert s3_canonical_id, "S3CanonicalUserId must be populated on create"

    def _cleanup() -> None:
        try:
            etag = cf.get_cloud_front_origin_access_identity(Id=oai_id)["ETag"]
        except cf.exceptions.NoSuchCloudFrontOriginAccessIdentity:
            return
        cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    got = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    assert got["CloudFrontOriginAccessIdentity"]["Id"] == oai_id
    assert got["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"] == s3_canonical_id
    got_cfg = cf.get_cloud_front_origin_access_identity_config(Id=oai_id)
    assert got_cfg["CloudFrontOriginAccessIdentityConfig"]["Comment"] == "sim2real-behav initial"
    assert got_cfg["ETag"] == create_etag

    updated = cf.update_cloud_front_origin_access_identity(
        Id=oai_id,
        IfMatch=create_etag,
        CloudFrontOriginAccessIdentityConfig={
            "CallerReference": caller_ref,
            "Comment": "sim2real-behav updated",
        },
    )
    update_etag = updated["ETag"]
    assert update_etag != create_etag, "ETag must change after a real config update"
    assert updated["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]["Comment"] == (
        "sim2real-behav updated"
    )
    assert updated["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"][
        "CallerReference"
    ] == caller_ref, "CallerReference is immutable and must survive an update unchanged"

    reread = cf.get_cloud_front_origin_access_identity_config(Id=oai_id)
    assert reread["CloudFrontOriginAccessIdentityConfig"]["Comment"] == "sim2real-behav updated"
    assert reread["ETag"] == update_etag

    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=update_etag)

    deleted = False
    try:
        cf.get_cloud_front_origin_access_identity(Id=oai_id)
    except cf.exceptions.NoSuchCloudFrontOriginAccessIdentity:
        deleted = True
    assert deleted, "OAI must be gone immediately after DeleteCloudFrontOriginAccessIdentity"

    mutation_rejected = False
    try:
        cf.update_cloud_front_origin_access_identity(
            Id=oai_id,
            IfMatch=update_etag,
            CloudFrontOriginAccessIdentityConfig={
                "CallerReference": caller_ref,
                "Comment": "post-delete-mutation",
            },
        )
    except cf.exceptions.NoSuchCloudFrontOriginAccessIdentity:
        mutation_rejected = True
    assert mutation_rejected, (
        "UpdateCloudFrontOriginAccessIdentity on a deleted OAI must fail with "
        "NoSuchCloudFrontOriginAccessIdentity, not silently succeed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
