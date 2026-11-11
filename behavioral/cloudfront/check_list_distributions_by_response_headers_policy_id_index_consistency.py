"""list-distributions-by-response-headers-policy-id-index-consistency."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-response-headers-policy-id-index-consistency"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1800.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return resp["ETag"]


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    etag = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_response_headers_policy(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_response_headers_policy(
        ResponseHeadersPolicyConfig={
            "Comment": "sim2real behavioral check response headers policy",
            "Name": ctx.unique_name("sim2real-rhp-"),
            "CustomHeadersConfig": {
                "Quantity": 1,
                "Items": [{"Header": "X-Sim2Real-Test", "Value": "true", "Override": False}],
            },
        }
    )
    policy_id = resp["ResponseHeadersPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_response_headers_policy(ctx, policy_id))
    return policy_id


def _delete_response_headers_policy(ctx, policy_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_response_headers_policy(Id=policy_id)["ETag"]
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=etag)


def _create_distribution(ctx, policy_id):
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-"),
            "Comment": "sim2real behavioral check distribution",
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "primary-origin",
                        "DomainName": origin_domain,
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "primary-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
                "ResponseHeadersPolicyId": policy_id,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    return dist_id


def _list_by_response_headers_policy(cf, policy_id):
    ids = set()
    marker = None
    while True:
        kwargs = {"ResponseHeadersPolicyId": policy_id, "MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_response_headers_policy_id(**kwargs)
        idlist = resp["DistributionIdList"]
        ids.update(idlist.get("Items", []))
        marker = idlist.get("NextMarker")
        if not marker:
            break
    return ids


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution using a response headers policy is enumerated by
    ListDistributionsByResponseHeadersPolicyId, and a bogus policy id is rejected with
    NoSuchResponseHeadersPolicy rather than an empty result."""
    cf = ctx.client("cloudfront")
    policy_id = _create_response_headers_policy(ctx)
    dist_id = _create_distribution(ctx, policy_id)

    ids = _poll_until(
        lambda: _list_by_response_headers_policy(cf, policy_id),
        lambda ids: dist_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id in ids, f"expected {dist_id!r} in ListDistributionsByResponseHeadersPolicyId, got {ids!r}"

    code, message = _error_code_and_message(
        lambda: cf.list_distributions_by_response_headers_policy_id(
            ResponseHeadersPolicyId="not-a-real-policy-id"
        )
    )
    assert code == "NoSuchResponseHeadersPolicy", f"expected NoSuchResponseHeadersPolicy, got {code!r}"
    assert message == "The specified response headers policy does not exist.", f"unexpected message {message!r}"

    # Positive control: the real policy id still resolves correctly after the bogus call.
    ids_again = _list_by_response_headers_policy(cf, policy_id)
    assert dist_id in ids_again, (
        f"expected {dist_id!r} still in ListDistributionsByResponseHeadersPolicyId after the "
        f"rejected bogus-id call, got {ids_again!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
