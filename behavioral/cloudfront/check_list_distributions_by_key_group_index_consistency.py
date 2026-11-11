"""list-distributions-by-key-group-index-consistency."""
from __future__ import annotations

import subprocess
import tempfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-key-group-index-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


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


def _generate_rsa_public_key_pem() -> str:
    with tempfile.TemporaryDirectory() as d:
        key_path = f"{d}/key.pem"
        pub_path = f"{d}/pub.pem"
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True, capture_output=True)
        subprocess.run(
            ["openssl", "rsa", "-in", key_path, "-pubout", "-out", pub_path], check=True, capture_output=True
        )
        with open(pub_path) as f:
            return f.read()


def _create_public_key(ctx) -> str:
    cf = ctx.client("cloudfront")
    pub_pem = _generate_rsa_public_key_pem()
    resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-pk-"),
            "Name": ctx.unique_name("sim2real-pk-"),
            "EncodedKey": pub_pem,
            "Comment": "sim2real test key",
        }
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(ctx, key_id))
    return key_id


def _delete_public_key(ctx, key_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_public_key(Id=key_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise
        return
    cf.delete_public_key(Id=key_id, IfMatch=etag)


def _create_key_group(ctx, public_key_id: str) -> str:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-kg-")
    resp = cf.create_key_group(KeyGroupConfig={"Name": name, "Items": [public_key_id]})
    key_group_id = resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, key_group_id))
    return key_group_id


def _delete_key_group(ctx, key_group_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_key_group(Id=key_group_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResource":
            raise
        return
    cf.delete_key_group(Id=key_group_id, IfMatch=etag)


def _create_distribution(ctx, key_group_id):
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
                "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [key_group_id]},
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


def _list_by_key_group(cf, key_group_id):
    ids = set()
    marker = None
    while True:
        kwargs = {"KeyGroupId": key_group_id, "MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_key_group(**kwargs)
        idlist = resp["DistributionIdList"]
        ids.update(idlist.get("Items", []))
        marker = idlist.get("NextMarker")
        if not marker:
            break
    return ids


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution trusting a key group is returned by ListDistributionsByKeyGroup;
    removing the trust (via UpdateDistribution) removes it from the index."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    public_key_id = _create_public_key(ctx)
    key_group_id = _create_key_group(ctx, public_key_id)
    dist_id = _create_distribution(ctx, key_group_id)

    ids_after_create = _poll_until(
        lambda: _list_by_key_group(cf, key_group_id),
        lambda ids: dist_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id in ids_after_create, (
        f"distribution {dist_id} trusting key group {key_group_id} never appeared in "
        f"ListDistributionsByKeyGroup (got {sorted(ids_after_create)})"
    )

    config_resp = cf.get_distribution_config(Id=dist_id)
    config = config_resp["DistributionConfig"]
    config["DefaultCacheBehavior"]["TrustedKeyGroups"] = {"Enabled": False, "Quantity": 0, "Items": []}
    cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=config_resp["ETag"])

    ids_after_remove = _poll_until(
        lambda: _list_by_key_group(cf, key_group_id),
        lambda ids: dist_id not in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id not in ids_after_remove, (
        f"distribution {dist_id} still listed under key group {key_group_id} in "
        f"ListDistributionsByKeyGroup after TrustedKeyGroups was disabled (got {sorted(ids_after_remove)})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
