"""create-distribution-rejects-cache-tag-header-with-illegal-characters."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-distribution-rejects-cache-tag-header-with-illegal-characters"
GROUP = "invalidation"
SERVICES = ["cloudfront"]

#: A header token with a space, which HTTP header names never carry.
_BAD_HEADER_NAME = "Bad Cache Tag Header"
#: A well-formed header token for the positive control. CloudFront echoes a header name back
#: lower-cased, so this is already lower-case to make the read-back assertion exact.
_GOOD_HEADER_NAME = "x-sim2real-cache-tags-control"

_ILLEGAL_HEADER_CHARS = (
    "InvalidArgument",
    f"The parameter CacheTagConfig:headerName contains {_BAD_HEADER_NAME} that has illegal characters.",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"got error code {err['Code']!r}, expected {code!r}"
        assert err["Message"] == message, f"got message {err['Message']!r}, expected {message!r}"
        return
    raise AssertionError(f"expected {code!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistribution refuses a CacheTagConfig.HeaderName with illegal characters, minting no
    distribution, while an otherwise identical config with a well-formed header name succeeds.
    """
    cf = ctx.client("cloudfront")
    bad_ref = ctx.unique_name("sim2real-cf-bad-")
    expect_error(
        lambda: cf.create_distribution(DistributionConfig=_distribution_config(bad_ref, _BAD_HEADER_NAME)),
        *_ILLEGAL_HEADER_CHARS,
    )

    good_ref = ctx.unique_name("sim2real-cf-good-")
    resp = cf.create_distribution(DistributionConfig=_distribution_config(good_ref, _GOOD_HEADER_NAME))
    did = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, did))
    assert resp["Distribution"]["DistributionConfig"]["CacheTagConfig"] == {
        "HeaderName": _GOOD_HEADER_NAME
    }, (
        f"a well-formed header name was echoed back as "
        f"{resp['Distribution']['DistributionConfig'].get('CacheTagConfig')!r}, expected "
        f"HeaderName {_GOOD_HEADER_NAME!r}"
    )

    read = cf.get_distribution_config(Id=did)["DistributionConfig"]
    assert read["CacheTagConfig"] == {"HeaderName": _GOOD_HEADER_NAME}, (
        f"GetDistributionConfig reports CacheTagConfig {read.get('CacheTagConfig')!r}, "
        f"expected HeaderName {_GOOD_HEADER_NAME!r}"
    )


#: AWS's managed "CachingOptimized" cache policy -- the id CDK's CachePolicy.CACHING_OPTIMIZED pins.
_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: A distribution can be deleted only once it is disabled and its last change has deployed,
#: which takes minutes; the teardown polls for that up to this deadline.
_DEPLOYED_DEADLINE_S = 900


def _distribution_config(ref: str, header_name: str) -> dict:
    return {
        "CallerReference": ref,
        "Comment": "sim2real cache-tag header validation check",
        "Enabled": False,
        "DefaultRootObject": "index.html",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "site",
            "DomainName": "example.com",
            "CustomOriginConfig": {
                "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
            },
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "site",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _CACHING_OPTIMIZED,
        },
        "CacheTagConfig": {"HeaderName": header_name},
    }


def _delete_distribution(ctx, did: str) -> None:
    """Wait for the last change to deploy, delete. A failure raises."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + _DEPLOYED_DEADLINE_S
    while True:
        try:
            got = cf.get_distribution(Id=did)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchDistribution":
                return
            raise
        dist = got["Distribution"]
        if dist["Status"] == "Deployed":
            cf.delete_distribution(Id=did, IfMatch=got["ETag"])
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"cloudfront distribution {did} not deletable within "
                f"{_DEPLOYED_DEADLINE_S}s (status {dist['Status']!r})"
            )
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
