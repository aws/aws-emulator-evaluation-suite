"""distribution-origin-custom-header-reserved-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-origin-custom-header-reserved-name-rejected"
GROUP = "distribution-lifecycle"
SERVICES = ["cloudfront"]

#: Managed CachingOptimized policy (AWS-owned public id; the distribution never serves).
_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: AWS's exact refusal for a CustomHeaders entry naming a header CloudFront reserves.
_RESERVED_HEADER = ("InvalidArgument", "The parameter HeaderName : Host is not allowed.")

#: AWS's exact refusal reading a distribution that no longer exists.
_NO_SUCH_DISTRIBUTION = ("NoSuchDistribution", "The specified distribution does not exist.")


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=15.0) -> str:
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete(cf, dist_id) -> None:
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _teardown_distribution(cf, dist_id):
    """A distribution already deleted by the body is not a leak."""
    def run_undo() -> None:
        try:
            _disable_and_delete(cf, dist_id)
        except cf.exceptions.NoSuchDistribution:
            return
    return run_undo


def _expect_error(fn, expected_code: str, expected_message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        got = (error.get("Code"), error.get("Message"))
        assert got == (expected_code, expected_message), (
            f"expected {(expected_code, expected_message)!r}, got {got!r}"
        )
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _headers_map(origin: dict) -> dict[str, str]:
    items = origin.get("CustomHeaders", {}).get("Items", [])
    return {h["HeaderName"]: h["HeaderValue"] for h in items}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDistribution refuses an origin CustomHeaders entry naming the reserved Host header
    and leaves the stored headers unchanged; a legal header name on the same origin still
    succeeds, and the distribution is unreadable by GetDistribution once deleted.
    """
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-behav-cfres-')}.s3.us-east-1.amazonaws.com"

    cfg = {
        "CallerReference": ctx.unique_name("sim2real-behav-cfres-"),
        "Comment": "sim2real origin reserved header rejection",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [{
                "Id": "guarded-origin",
                "DomainName": origin_domain,
                "S3OriginConfig": {"OriginAccessIdentity": ""},
                "CustomHeaders": {
                    "Quantity": 1,
                    "Items": [{"HeaderName": "X-Custom-Auth", "HeaderValue": "guard-token-1"}],
                },
            }],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "guarded-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
    }

    dist_id = cf.create_distribution(DistributionConfig=cfg)["Distribution"]["Id"]
    ctx.on_cleanup(_teardown_distribution(cf, dist_id))

    cfg_resp = cf.get_distribution_config(Id=dist_id)
    etag = cfg_resp["ETag"]
    reserved_cfg = cfg_resp["DistributionConfig"]
    reserved_cfg["Origins"]["Items"][0]["CustomHeaders"] = {
        "Quantity": 1,
        "Items": [{"HeaderName": "Host", "HeaderValue": "example.com"}],
    }
    _expect_error(
        lambda: cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=reserved_cfg),
        *_RESERVED_HEADER,
    )

    unchanged = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    unchanged_origin = unchanged["Origins"]["Items"][0]
    assert unchanged_origin["CustomHeaders"]["Quantity"] == 1, unchanged_origin["CustomHeaders"]
    assert _headers_map(unchanged_origin) == {"X-Custom-Auth": "guard-token-1"}, (
        unchanged_origin["CustomHeaders"]
    )

    # Positive control: the same origin accepts a second LEGAL header name on the same call shape
    # that the reserved name was refused on, proving the refusal is specific to "Host".
    legal_cfg_resp = cf.get_distribution_config(Id=dist_id)
    legal_etag = legal_cfg_resp["ETag"]
    legal_cfg = legal_cfg_resp["DistributionConfig"]
    legal_cfg["Origins"]["Items"][0]["CustomHeaders"] = {
        "Quantity": 2,
        "Items": [
            {"HeaderName": "X-Custom-Auth", "HeaderValue": "guard-token-1"},
            {"HeaderName": "X-Custom-Region", "HeaderValue": "us-west-2"},
        ],
    }
    cf.update_distribution(Id=dist_id, IfMatch=legal_etag, DistributionConfig=legal_cfg)

    after_legal = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    after_legal_origin = after_legal["Origins"]["Items"][0]
    assert after_legal_origin["CustomHeaders"]["Quantity"] == 2, after_legal_origin["CustomHeaders"]
    assert _headers_map(after_legal_origin) == {
        "X-Custom-Auth": "guard-token-1",
        "X-Custom-Region": "us-west-2",
    }, after_legal_origin["CustomHeaders"]

    _disable_and_delete(cf, dist_id)

    _expect_error(lambda: cf.get_distribution(Id=dist_id), *_NO_SUCH_DISTRIBUTION)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
