"""list-distributions-by-key-group-filters-correctly."""
from __future__ import annotations

import subprocess
import time

from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "list-distributions-by-key-group-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByKeyGroup returns only the distribution whose default cache behavior
    trusts a given key group, not an unrelated control distribution without it."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    managed_tag = {"Items": [{"Key": "sim2real:managed", "Value": "true"}]}

    pem = _generate_rsa_public_key_pem()
    key_ref = ctx.unique_name("sim2real-kg-pubkey-")
    public_key_id = cf.create_public_key(
        PublicKeyConfig={"CallerReference": key_ref, "Name": key_ref, "EncodedKey": pem}
    )["PublicKey"]["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_public_key(Id=public_key_id, IfMatch=cf.get_public_key(Id=public_key_id)["ETag"])
    )

    group_ref = ctx.unique_name("sim2real-keygroup-")
    key_group_id = cf.create_key_group(
        KeyGroupConfig={"Name": group_ref, "Items": [public_key_id]}
    )["KeyGroup"]["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_key_group(Id=key_group_id, IfMatch=cf.get_key_group(Id=key_group_id)["ETag"])
    )

    trusted_key_groups = {"Enabled": True, "Quantity": 1, "Items": [key_group_id]}
    wired_id = _create_distribution(
        ctx, cf, ctx.unique_name("sim2real-kg-wired-"), TrustedKeyGroups=trusted_key_groups
    )
    control_id = _create_distribution(ctx, cf, ctx.unique_name("sim2real-kg-ctrl-"))
    for dist_id in (wired_id, control_id):
        cf.tag_resource(
            Resource=f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}", Tags=managed_tag
        )

    resp = cf.list_distributions_by_key_group(KeyGroupId=key_group_id)
    ids = set(resp["DistributionIdList"].get("Items", []))
    assert wired_id in ids, f"expected wired distribution {wired_id} in {ids}"
    assert control_id not in ids, f"control distribution {control_id} unexpectedly in {ids}"


def _generate_rsa_public_key_pem() -> str:
    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True, timeout=30
    ).stdout
    return pub.decode("ascii")


def _create_distribution(ctx, cf, ref: str, **default_cache_behavior_overrides) -> str:
    ref = ref.lower()
    origin_id = "origin1"
    default_cache_behavior = {
        "TargetOriginId": origin_id,
        "ViewerProtocolPolicy": "allow-all",
        "CachePolicyId": _MANAGED_CACHING_DISABLED_POLICY_ID,
    }
    default_cache_behavior.update(default_cache_behavior_overrides)
    config = {
        "CallerReference": ref,
        "Comment": "sim2real-behav cloudfront check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{ref}.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "match-viewer",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": default_cache_behavior,
    }
    dist_id = cf.create_distribution(DistributionConfig=config)["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id


def _delete_distribution(cf, dist_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
