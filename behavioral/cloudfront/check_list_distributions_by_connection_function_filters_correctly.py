"""list-distributions-by-connection-function-filters-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-connection-function-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]

_CONNECTION_FUNCTION_CODE = b"function connectionHandler(connection) { connection.allow(); }"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByConnectionFunction returns exactly the distributions whose
    DistributionConfig.ConnectionFunctionAssociation references the given (published)
    connection function, and excludes a sibling distribution that isn't wired to it."""
    cf = ctx.client("cloudfront")

    fn_name = ctx.unique_name("sim2real-connfn-").replace("_", "-")
    create_resp = cf.create_connection_function(
        Name=fn_name,
        ConnectionFunctionConfig={"Comment": "list-by-connection-function check", "Runtime": "cloudfront-js-2.0"},
        ConnectionFunctionCode=_CONNECTION_FUNCTION_CODE,
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    fn_id = create_resp["ConnectionFunctionSummary"]["Id"]
    fn_etag = create_resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_connection_function(
        Id=fn_id, IfMatch=cf.get_connection_function(Id=fn_id)["ETag"]
    ))
    cf.publish_connection_function(Id=fn_id, IfMatch=fn_etag)

    wired_id = _create_distribution(ctx, "connfn-filter wired", connection_function_id=fn_id)
    unwired_id = _create_distribution(ctx, "connfn-filter unwired", connection_function_id=None)

    # The connection-function index lags distribution creation, so a single unretried listing call
    # flakes on a correct target. Poll until the wired distribution is indexed, then read the
    # absence of the unwired one off that same call — the twin was created in the same instant, so
    # one snapshot settles both.
    filtered_ids = _poll_until(
        lambda: _collect_all_ids(cf.list_distributions_by_connection_function, ConnectionFunctionIdentifier=fn_id),
        lambda ids: wired_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert wired_id in filtered_ids, "the wired distribution is missing from the filtered list"
    assert unwired_id not in filtered_ids, "an unrelated distribution leaked into the filtered list"


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _collect_all_ids(list_fn, **kwargs) -> set[str]:
    ids: set[str] = set()
    marker = None
    while True:
        params = dict(kwargs)
        params["MaxItems"] = 100
        if marker:
            params["Marker"] = marker
        resp = list_fn(**params)
        body = resp["DistributionList"]
        for item in body.get("Items", []):
            ids.add(item["Id"])
        if not body.get("IsTruncated"):
            break
        marker = body.get("NextMarker")
        if not marker:
            break
    return ids


def _create_distribution(ctx, comment: str, connection_function_id) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-connfn-dist-")
    config = {
        "CallerReference": caller_ref,
        "Comment": comment,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    if connection_function_id:
        config["DefaultCacheBehavior"]["ViewerProtocolPolicy"] = "https-only"
        config["ConnectionFunctionAssociation"] = {"Id": connection_function_id}
        config["ViewerMtlsConfig"] = {"Mode": "passthrough"}
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
