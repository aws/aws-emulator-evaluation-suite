"""origin-with-both-oac-and-oai-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "origin-with-both-oac-and-oai-rejected"
GROUP = "origin-access-control"
SERVICES = ["cloudfront", "s3"]

#: CloudFront's control plane is global and lives only in us-east-1; the bucket is in ctx.region.
CLOUDFRONT_REGION = "us-east-1"


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CreateDistribution with an S3 origin naming both a valid OAC and a valid OAI is refused with
    IllegalOriginAccessConfiguration, HTTP 400 and its exact message; no distribution is created, and both
    principals then delete at once and read back as their exact not-found errors.
    """
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-xsvc-cfboth-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cfboth-oac-"),
        "Description": "sim2real origin-with-both-oac-and-oai-rejected",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_if_present(cf.get_origin_access_control,
                                              cf.delete_origin_access_control, oac_id))

    oai = cf.create_cloud_front_origin_access_identity(CloudFrontOriginAccessIdentityConfig={
        "CallerReference": ctx.unique_name("sim2real-xsvc-cfboth-oai-"),
        "Comment": "sim2real origin-with-both-oac-and-oai-rejected",
    })["CloudFrontOriginAccessIdentity"]
    oai_id = oai["Id"]
    ctx.on_cleanup(lambda: _delete_if_present(cf.get_cloud_front_origin_access_identity,
                                              cf.delete_cloud_front_origin_access_identity, oai_id))

    # POSITIVE CONTROLS: both principals exist and are well-formed, so a refusal cannot be a
    # dangling-id error.
    got_oac = cf.get_origin_access_control(Id=oac_id)["OriginAccessControl"]
    assert got_oac["Id"] == oac_id, f"GetOriginAccessControl returned id {got_oac['Id']!r}"
    assert got_oac["OriginAccessControlConfig"]["OriginAccessControlOriginType"] == "s3", (
        f"OAC origin type is {got_oac['OriginAccessControlConfig']!r}, expected s3"
    )
    got_oai = cf.get_cloud_front_origin_access_identity(Id=oai_id)["CloudFrontOriginAccessIdentity"]
    assert got_oai["Id"] == oai_id, f"GetCloudFrontOriginAccessIdentity returned {got_oai['Id']!r}"
    assert got_oai["S3CanonicalUserId"], f"OAI has no S3CanonicalUserId: {got_oai!r}"

    comment = ctx.unique_name("sim2real-xsvc-cfboth-dist-")
    config = {
        "CallerReference": comment,
        "Comment": comment,
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": f"origin-access-identity/cloudfront/{oai_id}"},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # managed CachingDisabled
        },
    }

    # THE NEGATIVE. The response is captured rather than asserted inline: if the target wrongly
    # accepts the config, a distribution exists and must get a teardown before we fail.
    try:
        created = cf.create_distribution(DistributionConfig=config)["Distribution"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
    else:
        ctx.on_cleanup(lambda: _delete_disabled_distribution(cf, created["Id"]))
        raise AssertionError(
            f"CreateDistribution ACCEPTED an origin with both OAC {oac_id!r} and OAI {oai_id!r}: "
            f"created {created['Id']!r}"
        )
    assert code == "IllegalOriginAccessConfiguration", (
        f"an origin with both OAC and OAI was refused with {code!r}, "
        f"expected IllegalOriginAccessConfiguration"
    )
    assert status == 400, f"IllegalOriginAccessConfiguration came back HTTP {status!r}, expected 400"
    expected = "Cannot use both Origin Access Control and Origin Access Identity on an origin"
    assert message == expected, f"IllegalOriginAccessConfiguration message {message!r}, expected {expected!r}"

    # EFFECT ABSENT: no distribution carries this run's unique comment.
    leaked = [d["Id"] for d in _distributions(cf) if d.get("Comment") == comment]
    assert leaked == [], f"the refused CreateDistribution still produced distributions {leaked!r}"

    # NOTHING LEFT REFERENCED: both principals delete at once. A half-committed distribution would
    # make these return *InUse.
    etag = cf.get_cloud_front_origin_access_identity(Id=oai_id)["ETag"]
    cf.delete_cloud_front_origin_access_identity(Id=oai_id, IfMatch=etag)
    etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)
    got = _error(lambda: cf.get_origin_access_control(Id=oac_id))
    assert got == ("NoSuchOriginAccessControl", "The specified origin access control does not exist."), (
        f"deleted OAC read back as {got!r}"
    )
    got = _error(lambda: cf.get_cloud_front_origin_access_identity(Id=oai_id))
    assert got == (
        "NoSuchCloudFrontOriginAccessIdentity",
        "The specified CloudFront origin access identity does not exist.",
    ), f"deleted OAI read back as {got!r}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the error fn raises. An unexpected SUCCESS raises rather than returning."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"call expected to fail succeeded: {str(result)[:300]!r}")


def _delete_if_present(get_fn, delete_fn, resource_id) -> None:
    try:
        etag = get_fn(Id=resource_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"].startswith("NoSuch"):
            return
        raise
    delete_fn(Id=resource_id, IfMatch=etag)


def _distributions(cf) -> list[dict]:
    items: list[dict] = []
    for page in cf.get_paginator("list_distributions").paginate():
        items.extend(page["DistributionList"].get("Items", []))
    return items


def _delete_disabled_distribution(cf, dist_id, timeout_s=1200.0) -> None:
    """Only reached when the target wrongly accepted the config (created with Enabled=False)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        r = cf.get_distribution(Id=dist_id)
        if r["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=r["ETag"])
            return
        time.sleep(15)
    raise AssertionError(f"distribution {dist_id} never reached Deployed for deletion")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
