"""origin-access-identity-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _force_delete_oai(cf, oai_id):
    """ETag-guarded delete of a CloudFrontOriginAccessIdentity; one the check already deleted is done."""
    try:
        resp = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchCloudFrontOriginAccessIdentity":
            return
        raise
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=resp["ETag"])

CHECK = "origin-access-identity-lifecycle"
GROUP = 'origin-access-control'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFrontOriginAccessIdentity CRUD: create -> get -> get-config -> list ->
    update -> delete -> get fails."""
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-behav-oai-")
    create_resp = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": ref, "Comment": "v1"}
    )
    oai_id = create_resp["CloudFrontOriginAccessIdentity"]["Id"]
    etag = create_resp["ETag"]
    ctx.on_cleanup(lambda: _force_delete_oai(cf, oai_id))
    assert create_resp["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"], (
        "expected CreateCloudFrontOriginAccessIdentity to populate S3CanonicalUserId"
    )

    get_resp = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    assert get_resp["ETag"] == etag, f"expected ETag {etag!r} on Get, got {get_resp['ETag']!r}"

    get_cfg_resp = cf.get_cloud_front_origin_access_identity_config(Id=oai_id)
    assert get_cfg_resp["ETag"] == etag, (
        f"expected ETag {etag!r} on GetConfig, got {get_cfg_resp['ETag']!r}"
    )
    assert get_cfg_resp["CloudFrontOriginAccessIdentityConfig"]["Comment"] == "v1", (
        f"expected Comment 'v1', got {get_cfg_resp['CloudFrontOriginAccessIdentityConfig']['Comment']!r}"
    )

    listed = cf.list_cloud_front_origin_access_identities()
    ids = [
        i["Id"]
        for i in listed["CloudFrontOriginAccessIdentityList"].get("Items", [])
    ]
    assert oai_id in ids, f"expected {oai_id} in ListCloudFrontOriginAccessIdentities, got {ids}"

    updated_cfg = {"CallerReference": ref, "Comment": "v2"}
    update_resp = cf.update_cloud_front_origin_access_identity(
        Id=oai_id, IfMatch=etag, CloudFrontOriginAccessIdentityConfig=updated_cfg
    )
    new_etag = update_resp["ETag"]
    assert new_etag != etag, f"expected ETag to rotate on update, still {etag!r}"
    updated_comment = update_resp["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"][
        "Comment"
    ]
    assert updated_comment == "v2", f"expected Comment 'v2' after update, got {updated_comment!r}"

    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=new_etag)
    code, msg = _error(lambda: cf.get_cloud_front_origin_access_identity(Id=oai_id))
    assert code == "NoSuchCloudFrontOriginAccessIdentity", (
        f"expected NoSuchCloudFrontOriginAccessIdentity after delete, got {code}"
    )
    assert msg == "The specified CloudFront origin access identity does not exist.", f"unexpected message after delete: {msg!r}"

    second_delete_code, second_delete_msg = _error(
        lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=new_etag)
    )
    assert second_delete_code == "NoSuchCloudFrontOriginAccessIdentity", (
        "expected a delete of an already-deleted OAI to fail not-found, "
        f"got {second_delete_code}"
    )
    assert second_delete_msg == "The specified CloudFront origin access identity does not exist.", f"unexpected message on second delete: {second_delete_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
