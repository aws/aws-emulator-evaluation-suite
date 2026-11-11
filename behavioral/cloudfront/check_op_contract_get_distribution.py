"""op-contract-get-distribution."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-distribution"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDistribution reflects the created config/status/domain, does not advance
    state across repeated reads, and 404s on unknown Id."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-dist-")
    dist_config = _minimal_distribution_config(ctx, caller_ref)
    created = cf.create_distribution(DistributionConfig=dist_config)
    dist = created["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))

    # basic create-time contract sanity
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", dist["DomainName"]), (
        f"expected a hostname DomainName, got {dist['DomainName']!r}"
    )
    assert dist["Status"] in ("InProgress", "Deployed"), (
        f"expected Status in (InProgress, Deployed), got {dist['Status']!r}"
    )

    # success-path contract
    got = cf.get_distribution(Id=dist_id)
    assert got["Distribution"]["Id"] == dist_id, (
        f"expected GetDistribution Id {dist_id!r}, got {got['Distribution']['Id']!r}"
    )
    assert got["Distribution"]["DomainName"] == dist["DomainName"], (
        f"expected DomainName {dist['DomainName']!r}, got {got['Distribution']['DomainName']!r}"
    )
    assert got["Distribution"]["Status"] in ("InProgress", "Deployed"), (
        f"expected Status in (InProgress, Deployed), got {got['Distribution']['Status']!r}"
    )
    assert got["Distribution"]["DistributionConfig"]["CallerReference"] == caller_ref, (
        f"expected CallerReference {caller_ref!r}, got "
        f"{got['Distribution']['DistributionConfig']['CallerReference']!r}"
    )
    assert "ETag" in got, f"expected an ETag on GetDistribution, got keys {sorted(got)}"

    # freeze detector: two independent reads with no mutation between them must
    # report the identical ETag/Status/LastModifiedTime — a read must not advance state.
    got2 = cf.get_distribution(Id=dist_id)
    assert got2["ETag"] == got["ETag"], (
        f"a read-only GetDistribution rotated the ETag: {got['ETag']!r} -> {got2['ETag']!r}"
    )
    assert got2["Distribution"]["Status"] == got["Distribution"]["Status"], (
        f"a read-only GetDistribution changed Status: {got['Distribution']['Status']!r} -> "
        f"{got2['Distribution']['Status']!r}"
    )
    assert got2["Distribution"]["LastModifiedTime"] == got["Distribution"]["LastModifiedTime"], (
        f"a read-only GetDistribution changed LastModifiedTime: "
        f"{got['Distribution']['LastModifiedTime']!r} -> {got2['Distribution']['LastModifiedTime']!r}"
    )

    # distinct error boundary: unknown Id (structurally unissuable — no restore leg)
    code, message = _error(lambda: cf.get_distribution(Id="E000000000ABCD"))
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution, got {code!r}"
    assert message == "The specified distribution does not exist.", (
        f"expected AWS's exact message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _minimal_distribution_config(ctx, caller_ref: str) -> dict:
    origin_domain = f"{ctx.unique_name('sim2real-origin-')}.example.com"
    return {
        "CallerReference": caller_ref,
        "Comment": "sim2real behavioral test distribution",
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
