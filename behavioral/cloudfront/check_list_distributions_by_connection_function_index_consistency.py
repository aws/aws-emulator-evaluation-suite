"""list-distributions-by-connection-function-index-consistency."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-connection-function-index-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

# ViewerMtlsConfig in "passthrough" mode only permits the Managed-CachingDisabled policy.
_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_CODE = (
    b"function connectionHandler(connection) {\n"
    b"  connection.allow();\n"
    b"}\n"
)


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


def _create_published_connection_function(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-connfn-")
    created = cf.create_connection_function(
        Name=name,
        ConnectionFunctionCode=_CODE,
        ConnectionFunctionConfig={
            "Comment": "sim2real behavioral check connection function",
            "Runtime": "cloudfront-js-2.0",
        },
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    fn_id = created["ConnectionFunctionSummary"]["Id"]
    ctx.on_cleanup(lambda: _delete_connection_function(ctx, fn_id))
    cf.publish_connection_function(Id=fn_id, IfMatch=created["ETag"])
    return fn_id


def _delete_connection_function(ctx, fn_id):
    cf = ctx.client("cloudfront")
    etag = cf.describe_connection_function(Identifier=fn_id, Stage="DEVELOPMENT")["ETag"]
    cf.delete_connection_function(Id=fn_id, IfMatch=etag)


def _create_distribution(ctx, **extra_config):
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    config = {
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
            # ViewerMtlsConfig requires every cache behavior to be HTTPS-only; a viewer mTLS
            # handshake has no HTTP equivalent.
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": _MANAGED_CACHING_DISABLED,
        },
        "ViewerMtlsConfig": {"Mode": "passthrough"},
    }
    config.update(extra_config)

    def _attempt():
        try:
            return cf.create_distribution(DistributionConfig=config)
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "InvalidArgument" and "publish is in progress" in error.get(
                "Message", ""
            ):
                # PublishConnectionFunction is itself asynchronous: real AWS briefly refuses to
                # associate a function that was just published until the publish settles.
                return None
            raise

    resp = _poll_until(_attempt, lambda r: r is not None, timeout_s=120.0, interval_s=5.0)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    return dist_id


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    etag = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _list_connfn_dist_ids(cf, fn_id):
    ids = set()
    marker = None
    while True:
        kwargs = {"ConnectionFunctionIdentifier": fn_id, "MaxItems": 100}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_connection_function(**kwargs)
        dlist = resp["DistributionList"]
        ids.update(item["Id"] for item in dlist.get("Items", []))
        marker = dlist.get("NextMarker")
        if not marker:
            break
    return ids


# ===== check =====

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution using a published connection function is enumerated by
    ListDistributionsByConnectionFunction; removing the function association removes it
    from the index."""
    cf = ctx.client("cloudfront")
    fn_id = _create_published_connection_function(ctx)
    dist_id = _create_distribution(ctx, ConnectionFunctionAssociation={"Id": fn_id})

    ids_after_create = _poll_until(
        lambda: _list_connfn_dist_ids(cf, fn_id),
        lambda ids: dist_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id in ids_after_create, (
        f"distribution {dist_id} with a live ConnectionFunctionAssociation for {fn_id} never "
        f"appeared in ListDistributionsByConnectionFunction, got {ids_after_create!r}"
    )

    config_resp = cf.get_distribution_config(Id=dist_id)
    config = config_resp["DistributionConfig"]
    config.pop("ConnectionFunctionAssociation", None)
    cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=config_resp["ETag"])

    ids_after_remove = _poll_until(
        lambda: _list_connfn_dist_ids(cf, fn_id),
        lambda ids: dist_id not in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id not in ids_after_remove, (
        f"distribution {dist_id} stayed in ListDistributionsByConnectionFunction for {fn_id} "
        f"after its ConnectionFunctionAssociation was removed, got {ids_after_remove!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
