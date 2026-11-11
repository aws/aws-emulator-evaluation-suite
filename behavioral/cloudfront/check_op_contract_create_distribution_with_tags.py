"""op-contract-create-distribution-with-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-distribution-with-tags"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistributionWithTags: tags submitted at creation are actually attached
    (visible via ListTagsForResource), and a reserved "aws:" tag key prefix is rejected
    with InvalidTagging and its exact message."""
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-distwt-")
    tag_key, tag_value = "sim2real-owner", "behavioral-check"
    config_with_tags = {
        "DistributionConfig": _minimal_distribution_config(caller_ref),
        "Tags": {"Items": [{"Key": tag_key, "Value": tag_value}]},
    }

    resp = cf.create_distribution_with_tags(DistributionConfigWithTags=config_with_tags)
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, dist_id))

    assert dist["Status"] == "InProgress", f"expected Status=InProgress right after create, got {dist['Status']!r}"
    tags = cf.list_tags_for_resource(Resource=dist["ARN"])["Tags"]["Items"]
    tag_map = {t["Key"]: t["Value"] for t in tags}
    assert tag_map.get(tag_key) == tag_value, f"tag not attached at creation: {tag_map}"

    # Error boundary: reserved "aws:" tag key prefix is rejected.
    bad_config = {
        "DistributionConfig": _minimal_distribution_config(ctx.unique_name("sim2real-behav-distwt-bad-")),
        "Tags": {"Items": [{"Key": "aws:reserved", "Value": "x"}]},
    }
    err = _client_error(lambda: cf.create_distribution_with_tags(DistributionConfigWithTags=bad_config))
    assert err["Code"] == "InvalidTagging", f"expected InvalidTagging, got {err['Code']}"
    expected = "Tag key cannot start with 'aws:'."
    assert err.get("Message") == expected, (
        f"InvalidTagging message {err.get('Message')!r}, expected {expected!r}"
    )

    deployed = _wait_deployed(cf, dist_id)
    assert deployed["Status"] == "Deployed", f"expected Deployed, got {deployed['Status']!r}"


def _minimal_distribution_config(caller_ref):
    return {
        "CallerReference": caller_ref,
        "Comment": caller_ref,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "primary-origin",
                    "DomainName": "example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "primary-origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # CachingOptimized
        },
    }


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_deployed(cf, dist_id, timeout_s=850.0, interval_s=15.0):
    """Poll GetDistribution until Status is Deployed; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        dist = cf.get_distribution(Id=dist_id)["Distribution"]
        status = dist["Status"]
        if status == "Deployed":
            return dist
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s, last={status!r}")


def _delete_distribution_best_effort(ctx, dist_id):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + 900.0
    try:
        while time.monotonic() < deadline:
            resp = cf.get_distribution(Id=dist_id)
            if resp["Distribution"]["Status"] == "Deployed":
                cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
                return
            time.sleep(15)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
