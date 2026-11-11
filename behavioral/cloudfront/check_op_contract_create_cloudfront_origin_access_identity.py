"""op-contract-create-cloudfront-origin-access-identity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-cloudfront-origin-access-identity"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCloudFrontOriginAccessIdentity: returns a usable S3CanonicalUserId that an
    independent read confirms was persisted, and rejects a duplicate CallerReference with
    CloudFrontOriginAccessIdentityAlreadyExists without creating a second OAI."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-oai-")
    config = {"CallerReference": caller_ref, "Comment": caller_ref}

    resp = cf.create_cloud_front_origin_access_identity(CloudFrontOriginAccessIdentityConfig=config)
    oai = resp["CloudFrontOriginAccessIdentity"]
    oai_id = oai["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag))

    assert oai["CloudFrontOriginAccessIdentityConfig"]["Comment"] == caller_ref, (
        f"expected Comment {caller_ref!r}, got {oai['CloudFrontOriginAccessIdentityConfig']['Comment']!r}"
    )
    assert oai["S3CanonicalUserId"], "S3CanonicalUserId must be populated"

    # Independent read: the create response is not just an echo, the OAI is really there.
    got = cf.get_cloud_front_origin_access_identity(Id=oai_id)
    assert got["ETag"] == etag, f"expected ETag {etag!r} on independent read, got {got['ETag']!r}"
    assert got["CloudFrontOriginAccessIdentity"]["S3CanonicalUserId"] == oai["S3CanonicalUserId"], (
        "independent read must report the same S3CanonicalUserId as the create response"
    )

    # Error boundary: reusing the same CallerReference is rejected, and creates no second OAI.
    code, message = _error(
        lambda: cf.create_cloud_front_origin_access_identity(
            CloudFrontOriginAccessIdentityConfig={"CallerReference": caller_ref, "Comment": "dup"}
        )
    )
    assert code == "CloudFrontOriginAccessIdentityAlreadyExists", f"unexpected code {code}"
    expected = "The caller reference you are using to create the CloudFront origin access identity is associated with another identity."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = cf.list_cloud_front_origin_access_identities()
    matches = [
        item["Id"]
        for item in listed["CloudFrontOriginAccessIdentityList"].get("Items", [])
        if item["Id"] == oai_id
    ]
    assert matches == [oai_id], (
        f"expected exactly the original OAI {oai_id!r} to survive the rejected duplicate, got {matches}"
    )


def _error(fn):
    """Call fn() and return the ClientError (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
