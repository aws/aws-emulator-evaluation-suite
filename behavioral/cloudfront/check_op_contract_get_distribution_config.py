"""op-contract-get-distribution-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-distribution-config"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDistributionConfig round-trips the raw DistributionConfig, 404s on unknown Id."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-distcfg-")
    comment = "sim2real behavioral test distribution config"
    dist_config = _minimal_distribution_config(ctx, caller_ref, comment)
    created = cf.create_distribution(DistributionConfig=dist_config)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cf.tag_resource(
        Resource=f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}",
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )

    # success-path contract
    got = cf.get_distribution_config(Id=dist_id)
    assert got["DistributionConfig"]["CallerReference"] == caller_ref, (
        f"expected CallerReference {caller_ref!r}, got {got['DistributionConfig']['CallerReference']!r}"
    )
    assert got["DistributionConfig"]["Comment"] == comment, (
        f"expected Comment {comment!r}, got {got['DistributionConfig']['Comment']!r}"
    )
    assert got["DistributionConfig"]["Enabled"] is False, (
        f"expected Enabled False, got {got['DistributionConfig']['Enabled']!r}"
    )
    assert "ETag" in got, f"expected ETag in GetDistributionConfig response, got keys {sorted(got)}"

    # distinct error boundary: unknown Id
    code, message = _error(lambda: cf.get_distribution_config(Id="E000000000ABCE"))
    assert code == "NoSuchDistribution", f"unexpected code {code}"
    not_found_message = "The specified distribution does not exist."
    assert message == not_found_message, f"expected message {not_found_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _minimal_distribution_config(ctx, caller_ref: str, comment: str) -> dict:
    origin_domain = f"{ctx.unique_name('sim2real-origin-')}.example.com"
    return {
        "CallerReference": caller_ref,
        "Comment": comment,
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
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # Managed-CachingOptimized
        },
    }


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 600.0, interval_s: float = 20.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        etag = resp["ETag"]
        if resp["Distribution"]["Status"] == "Deployed":
            return etag
        time.sleep(interval_s)
    return etag


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        etag = cfg_resp["ETag"]
        config = cfg_resp["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            upd = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
            etag = upd["ETag"]
        etag = _wait_distribution_deployed(ctx, dist_id) or etag
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
