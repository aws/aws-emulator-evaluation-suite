"""update-oai-callerreference-immutable-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-oai-callerreference-immutable-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCloudFrontOriginAccessIdentity rejects a changed CallerReference
    (an immutable field) with IllegalUpdate, and leaves the identity untouched."""
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-oai-immutable-")
    created = cf.create_cloud_front_origin_access_identity(
        CloudFrontOriginAccessIdentityConfig={"CallerReference": ref, "Comment": "original"}
    )
    oai_id = created["CloudFrontOriginAccessIdentity"]["Id"]
    etag = created["ETag"]

    def _cleanup():
        latest = cf.get_cloud_front_origin_access_identity(Id=oai_id)["ETag"]
        cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=latest)

    ctx.on_cleanup(_cleanup)

    def _mutate_caller_reference():
        cf.update_cloud_front_origin_access_identity(
            Id=oai_id,
            IfMatch=etag,
            CloudFrontOriginAccessIdentityConfig={
                "CallerReference": ref + "-mutated",
                "Comment": "attempted mutation of immutable CallerReference",
            },
        )

    code, message = _error(_mutate_caller_reference)
    assert code == "IllegalUpdate", f"expected IllegalUpdate for CallerReference mutation, got {code}"
    expected_message = "You cannot update the value of CallerReference."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Confirm the rejected update did not leak through and mutate resource state.
    got = cf.get_cloud_front_origin_access_identity_config(Id=oai_id)
    got_cfg = got["CloudFrontOriginAccessIdentityConfig"]
    assert got_cfg["CallerReference"] == ref, (
        f"a rejected update must not mutate CallerReference: {ref!r} -> {got_cfg['CallerReference']!r}"
    )
    assert got_cfg["Comment"] == "original", (
        f"a rejected update must not mutate Comment either: 'original' -> {got_cfg['Comment']!r}"
    )

    # Positive control: the identical resource still accepts a legitimate update
    # (same CallerReference, changed Comment) with the ORIGINAL ETag, proving the
    # rejection above was specifically about CallerReference and not a generally
    # broken account/resource/credentials.
    ok = cf.update_cloud_front_origin_access_identity(
        Id=oai_id,
        IfMatch=etag,
        CloudFrontOriginAccessIdentityConfig={"CallerReference": ref, "Comment": "updated legitimately"},
    )
    ok_cfg = ok["CloudFrontOriginAccessIdentity"]["CloudFrontOriginAccessIdentityConfig"]
    assert ok_cfg["CallerReference"] == ref, (
        f"a successful update must still report the original CallerReference, got {ok_cfg['CallerReference']!r}"
    )
    assert ok_cfg["Comment"] == "updated legitimately", (
        f"expected the legitimate Comment update to take effect, got {ok_cfg['Comment']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
