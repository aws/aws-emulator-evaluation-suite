"""distribution-get-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-get-nonexistent-not-found"
GROUP = 'distribution-errors'
SERVICES = ['cloudfront']

_MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_NO_SUCH_DISTRIBUTION = "The specified distribution does not exist."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDistribution on an id never created returns NoSuchDistribution and the exact message, the same
    call on a real distribution returns it, and after that distribution is deleted its id returns the
    same not-found answer."""
    cf = ctx.client("cloudfront")

    code, message = _error(lambda: cf.get_distribution(Id="EDFAKE0000000"))
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution, got {code}"
    assert message == _NO_SUCH_DISTRIBUTION, f"expected {_NO_SUCH_DISTRIBUTION!r}, got {message!r}"

    caller_ref = ctx.unique_name("sim2real-dist-get-nf-")
    origin_domain = f"{ctx.unique_name('sim2real-origin-get-nf-')}.example.com"
    config_with_tags = {
        "DistributionConfig": {
            "CallerReference": caller_ref,
            "Comment": "get-nonexistent positive control",
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "origin1",
                        "DomainName": origin_domain,
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                            "OriginReadTimeout": 30,
                            "OriginKeepaliveTimeout": 5,
                        },
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "origin1",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID,
            },
        },
        "Tags": {"Items": [{"Key": "sim2real", "Value": caller_ref}]},
    }
    created = cf.create_distribution_with_tags(DistributionConfigWithTags=config_with_tags)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    # Positive control: the real distribution is retrievable through the very
    # operation the negative probe used, so "rejects an unknown id" cannot be
    # confused with "rejects every GetDistribution call".
    got = cf.get_distribution(Id=dist_id)
    got_id = got["Distribution"]["Id"]
    assert got_id == dist_id, f"expected the created distribution {dist_id}, got {got_id}"
    got_ref = got["Distribution"]["DistributionConfig"]["CallerReference"]
    assert got_ref == caller_ref, f"expected CallerReference {caller_ref}, got {got_ref}"

    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

    # Independent read after the delete: the identifier that just worked answers the
    # identical not-found code, not merely "was never created".
    code, message = _error(lambda: cf.get_distribution(Id=dist_id))
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution after delete, got {code}"
    assert message == _NO_SUCH_DISTRIBUTION, (
        f"expected {_NO_SUCH_DISTRIBUTION!r} after delete, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises,
    so a target that accepts what it should refuse fails as an accepted call."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _wait_distribution_deployed(cf, dist_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        etag = resp["ETag"]
        if resp["Distribution"]["Status"] == "Deployed":
            return etag
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s")


def _force_delete_distribution(cf, dist_id):
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return  # the check body already deleted it
        raise
    etag = cfg_resp["ETag"]
    config = cfg_resp["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id) or etag
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
