"""xsvc-cloudfront-3-standard-logging-v2-access-log-reaches-log-group."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "xsvc-cloudfront-3-standard-logging-v2-access-log-reaches-log-group"
GROUP = "data-plane"
SERVICES = ["cloudfront", "logs"]

#: CloudFront standard logging v2 is a us-east-1-only control plane: PutDeliverySource for a
#: distribution's ACCESS_LOGS is rejected in every other region (ValidationException
#: "PutDeliverySource action is not supported for this LogType in region us-west-2"), so the
#: delivery source, destination, delivery and destination log group all live there. This literal is
#: a region-pinned resource, not an account assumption.
_LOGS_REGION = "us-east-1"
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout - never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=10.0) -> str:
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_wait(cf, dist_id) -> str:
    """Disable the distribution and wait for that change to deploy; return the ETag to delete with.
    Called at the END of the check body: the engine bounds the whole cleanup chain at 60 s, and a
    disable round trip takes minutes, so the slow half of teardown cannot live in a cleanup."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    return _wait_distribution_deployed(cf, dist_id)


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Cleanup: delete at once if the body already disabled it; otherwise disable and give the
    change a bounded window, then report the leak."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        r = cf.get_distribution(Id=dist_id)
        if r["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=r["ETag"])
            return
        time.sleep(5)
    raise RuntimeError(
        f"cloudfront distribution {dist_id} still deploying its disable; not deleted"
    )


def _retry_in_use(fn, *, timeout_s=20.0) -> None:
    """A resource a just-deleted distribution referenced can stay in-use for a few seconds."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # botocore ClientError
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if "InUse" not in code or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _delete_group_policy(logs, resource_arn) -> None:
    """Delete a log-group-scoped resource policy at its CURRENT revision; absent is done."""
    from botocore.exceptions import ClientError

    try:
        policies = logs.describe_resource_policies(
            resourceArn=resource_arn, policyScope="RESOURCE")["resourcePolicies"]
        for policy in policies:
            logs.delete_resource_policy(resourceArn=resource_arn,
                                        expectedRevisionId=policy["revisionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_bucket(ctx, s3, bucket) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAG_SET})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _fetch_ok(session, url, *, timeout_s=240.0, interval_s=5.0):
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, timeout=15)
        except requests.RequestException as exc:  # transport only, during edge propagation
            last = exc
            return None
        return last

    try:
        return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


def _filter_all(logs, group, pattern) -> list[dict]:
    out: list[dict] = []
    for page in logs.get_paginator("filter_log_events").paginate(
            logGroupName=group, filterPattern=pattern):
        out.extend(page.get("events", []))
    return out


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:metrics",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Standard logging v2: a distribution registered as an ACCESS_LOGS delivery source delivers an
    access-log record for a real edge GET to the destination log group, read back via
    FilterLogEvents with the minted URI stem, status 200 and the distribution's host header.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    logs = ctx.client("logs", region=_LOGS_REGION)

    group = ctx.unique_name("/sim2real/xsvc/cflogs-")
    logs.create_log_group(logGroupName=group, tags={"sim2real": "behavioral"})
    ctx.on_cleanup(lambda: ctx.client("logs", region=_LOGS_REGION).delete_log_group(
        logGroupName=group))
    group_arn = next(g["arn"] for g in logs.describe_log_groups(
        logGroupNamePrefix=group)["logGroups"] if g["logGroupName"] == group)
    group_arn_bare = group_arn[:-2] if group_arn.endswith(":*") else group_arn

    bucket = ctx.unique_name("sim2real-xsvc-cflogs-").lower()
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    key = f"{ctx.unique_name('probe-')}.txt"
    body = b"sim2real-standard-logging-v2-probe"
    s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-xsvc-cflogs-oac-"),
        "OriginAccessControlOriginType": "s3", "SigningBehavior": "always",
        "SigningProtocol": "sigv4"})["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _retry_in_use(lambda: _delete_with_etag(
        cf.get_origin_access_control, cf.delete_origin_access_control, oac_id)))
    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-xsvc-cflogs-cr-"),
        "Comment": "sim2real standard logging v2",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3origin", "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": oac_id}]},
        "DefaultCacheBehavior": {"TargetOriginId": "s3origin", "ViewerProtocolPolicy": "allow-all",
                                 "CachePolicyId": MANAGED_CACHING_DISABLED},
    })["Distribution"]
    dist_id, dist_arn = dist["Id"], dist["ARN"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx.client("cloudfront"), dist_id))
    cf.tag_resource(Resource=dist_arn, Tags={"Items": _TAG_SET})
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}}}]}))

    # A log-group-scoped resource policy (PutResourcePolicy with resourceArn), NOT the account-wide
    # one, so no sibling run's delivery is touched.
    logs.put_resource_policy(resourceArn=group_arn_bare, policyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "delivery.logs.amazonaws.com"},
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"{group_arn_bare}:log-stream:*",
            "Condition": {"StringEquals": {"aws:SourceAccount": dist_arn.split(":")[4]},
                          "ArnLike": {"aws:SourceArn": f"arn:aws:logs:{_LOGS_REGION}:"
                                                       f"{dist_arn.split(':')[4]}:*"}}}]}))
    ctx.on_cleanup(lambda: _delete_group_policy(ctx.client("logs", region=_LOGS_REGION),
                                                group_arn_bare))

    src_name = ctx.unique_name("sim2real-xsvc-cflogs-src-")
    src = logs.put_delivery_source(name=src_name, resourceArn=dist_arn, logType="ACCESS_LOGS",
                                   tags={"sim2real": "behavioral"})["deliverySource"]
    ctx.on_cleanup(lambda: ctx.client("logs", region=_LOGS_REGION).delete_delivery_source(
        name=src_name))
    assert src["service"] == "cloudfront" and src["logType"] == "ACCESS_LOGS", (
        f"the delivery source must be a cloudfront ACCESS_LOGS source, got {src!r}"
    )
    assert src["resourceArns"] == [dist_arn], (
        f"the delivery source must point at this distribution {dist_arn!r}, got "
        f"{src['resourceArns']!r}"
    )

    dst_name = ctx.unique_name("sim2real-xsvc-cflogs-dst-")
    dst = logs.put_delivery_destination(
        name=dst_name, outputFormat="json",
        deliveryDestinationConfiguration={"destinationResourceArn": group_arn_bare},
        tags={"sim2real": "behavioral"})["deliveryDestination"]
    ctx.on_cleanup(lambda: ctx.client("logs", region=_LOGS_REGION)
                   .delete_delivery_destination(name=dst_name))
    delivery = logs.create_delivery(deliverySourceName=src_name,
                                    deliveryDestinationArn=dst["arn"],
                                    tags={"sim2real": "behavioral"})["delivery"]
    ctx.on_cleanup(lambda: ctx.client("logs", region=_LOGS_REGION).delete_delivery(
        id=delivery["id"]))
    assert delivery["deliveryDestinationType"] == "CWL", (
        f"a log-group destination must be a CWL delivery, got {delivery!r}"
    )

    _wait_distribution_deployed(cf, dist_id)
    session = requests.Session()
    session.verify = ctx.http_verify
    edge, route_headers = ctx.endpoint_route(dist["DomainName"])
    session.headers.update(route_headers)
    served = _fetch_ok(session, f"{edge}/{key}")
    assert served.content == body, f"the edge served the wrong bytes: {served.content[:120]!r}"

    def records():
        out = []
        for ev in _filter_all(logs, group, f'"{key}"'):
            try:
                out.append(json.loads(ev["message"]))
            except ValueError:
                out.append({"_raw": ev["message"]})
        return out

    found = _poll_until(records, lambda r: len(r) >= 1, timeout_s=900.0, interval_s=20.0,
                        description=f"an access-log record naming {key!r} in log group {group}")
    rec = found[0]
    assert rec.get("cs-uri-stem") == f"/{key}", (
        f"the access-log record must carry the requested URI stem '/{key}', got {rec!r}"
    )
    assert str(rec.get("sc-status")) == "200", (
        f"the access-log record must carry the status the edge answered (200), got {rec!r}"
    )
    assert rec.get("x-host-header") == dist["DomainName"], (
        f"the access-log record must name this distribution's domain {dist['DomainName']!r}, got "
        f"{rec!r}"
    )

    # Teardown's slow half, in the body (the engine bounds cleanup at 60 s): the disable must
    # deploy before the distribution can be deleted.
    _disable_and_wait(cf, dist_id)
    assert cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["Enabled"] is False, (
        f"distribution {dist_id} must read back disabled after the disable deployed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
