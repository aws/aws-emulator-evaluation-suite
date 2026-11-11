"""obs-cloudfront-3-standard-log-fields-hit-miss-and-disabled-control-silent."""
from __future__ import annotations

import gzip
import json
import time

import requests

from behavioral_harness import tags

CHECK = "obs-cloudfront-3-standard-log-fields-hit-miss-and-disabled-control-silent"
GROUP = "log-delivery"
SERVICES = ["cloudfront", "s3"]

#: Managed CachingOptimized: the second request for the same object is served from the edge, so a
#: Hit and a Miss line can both be produced deliberately.
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: The documented standard-log (legacy) field set, in documented order;
#: DescribeConfigurationTemplates(service=cloudfront, ACCESS_LOGS)'s
#: defaultDeliveryConfigValues.recordFields lists the same 33 names in the same order.
DOCUMENTED_FIELDS = [
    "date", "time", "x-edge-location", "sc-bytes", "c-ip", "cs-method", "cs(Host)", "cs-uri-stem",
    "sc-status", "cs(Referer)", "cs(User-Agent)", "cs-uri-query", "cs(Cookie)", "x-edge-result-type",
    "x-edge-request-id", "x-host-header", "cs-protocol", "cs-bytes", "time-taken", "x-forwarded-for",
    "ssl-protocol", "ssl-cipher", "x-edge-response-result-type", "cs-protocol-version", "fle-status",
    "fle-encrypted-fields", "c-port", "time-to-first-byte", "x-edge-detailed-result-type",
    "sc-content-type", "sc-content-len", "sc-range-start", "sc-range-end",
]

LOG_PREFIX = "cf-std/"

_TAGS = [{"Key": "sim2real", "Value": "obs-cloudfront-3"}]


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description} (last: {last!r})")


def _dist_status(cf, dist_id):
    r = cf.get_distribution(Id=dist_id)
    return r["Distribution"]["Status"], r["ETag"]


def _wait_deployed(cf, dist_id, timeout_s=1500.0) -> str:
    return _poll_until(lambda: _dist_status(cf, dist_id), lambda s: s[0] == "Deployed",
                       timeout_s=timeout_s, interval_s=15.0,
                       description=f"distribution {dist_id} to reach Deployed")[1]


def _code(exc) -> str:
    return ((getattr(exc, "response", None) or {}).get("Error") or {}).get("Code", "")


def _teardown_distributions(cf, dist_ids, timeout_s=1500.0) -> None:
    """Disable, wait for Deployed, delete -- called from the check body on the success path,
    since disable -> Deployed takes minutes."""
    for dist_id in dist_ids:
        resp = cf.get_distribution_config(Id=dist_id)
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    for dist_id in dist_ids:
        cf.delete_distribution(Id=dist_id, IfMatch=_wait_deployed(cf, dist_id, timeout_s))


def _release_distribution(cf, dist_id) -> None:
    """Failure-path net, a few calls only: delete if already disabled and Deployed, else disable
    and report the distribution that is left to delete."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchDistribution":
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc
        return
    try:
        cfg = resp["DistributionConfig"]
        if cfg["Enabled"]:
            cfg["Enabled"] = False
            cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled by cleanup, delete pending"
            )
        cur = cf.get_distribution(Id=dist_id)
        if cur["Distribution"]["Status"] != "Deployed":
            raise RuntimeError(
                f"cloudfront distribution {dist_id}: disabled, still deploying, delete pending"
            )
        cf.delete_distribution(Id=dist_id, IfMatch=cur["ETag"])
    except Exception as exc:  # noqa: BLE001 - only a not-found is tolerated
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if teardown_code not in ("NoSuchDistribution",):
            raise RuntimeError(f"cloudfront distribution {dist_id}: {exc!r}") from exc


def _retry_in_use(fn, timeout_s=120.0) -> None:
    """A dependent of a just-deleted distribution can briefly still read as *InUse."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            if not _code(exc).endswith("InUse") or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _delete_oac(cf, oac_id) -> None:
    cf.delete_origin_access_control(Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"])


def _delete_oac_if_present(cf, oac_id) -> None:
    try:
        _delete_oac(cf, oac_id)
    except Exception as exc:  # noqa: BLE001
        if _code(exc) != "NoSuchOriginAccessControl":
            raise RuntimeError(
                f"cloudfront origin access control {oac_id}: {exc!r}"
            ) from exc


def _create_bucket(ctx, s3, bucket) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _get(url, route_headers, user_agent, verify):
    try:
        resp = requests.get(url, headers={"User-Agent": user_agent, **route_headers}, timeout=20,
                            verify=verify)
    except requests.RequestException:  # transport only, during edge propagation
        return None, {}
    return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}


def _served(url, route_headers, user_agent, verify):
    """GET until 200 with an X-Amz-Cf-Id; return (request_id, X-Cache first word)."""
    _status, headers = _poll_until(
        lambda: _get(url, route_headers, user_agent, verify),
        lambda r: r[0] == 200 and "x-amz-cf-id" in r[1],
        timeout_s=240.0, interval_s=5.0, description=f"HTTP 200 from {url}")
    x_cache = headers.get("x-cache", "")
    assert x_cache.endswith(" from cloudfront"), f"X-Cache must say how {url} was served, got {x_cache!r}"
    return headers["x-amz-cf-id"], x_cache.split(" ", 1)[0]


def _log_files(s3, bucket) -> dict:
    """{key: decoded text} for every object in the log bucket (all prefixes, paginated)."""
    out = {}
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            raw = s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read()
            out[obj["Key"]] = gzip.decompress(raw).decode("utf-8")
    return out


def _parse(text):
    """(fields, [column lists]) of one standard-log file."""
    fields, rows = None, []
    for line in text.splitlines():
        if line.startswith("#Fields:"):
            fields = line[len("#Fields:"):].split()
        elif line and not line.startswith("#"):
            rows.append(line.split("\t"))
    return fields, rows
# ===== end helpers =====


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Standard (legacy) access logs: the #Fields header is the documented 33-field set and matches
    every line's column count, Hit and Miss are told apart per request, request ids are distinct,
    and an IDENTICAL distribution with Logging.Enabled=false delivers nothing to the same bucket.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    content_bucket = ctx.unique_name("sim2real-obs3-std-src-").lower()
    _create_bucket(ctx, s3, content_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, content_bucket))
    key = f"{ctx.unique_name('obj-')}.txt"
    s3.put_object(Bucket=content_bucket, Key=key, Body=b"sim2real-obs-cloudfront-3-std",
                  ContentType="text/plain")

    # Standard logging writes via an ACL grant CloudFront adds itself, so ACLs must be enabled.
    log_bucket = ctx.unique_name("sim2real-obs3-std-log-").lower()
    _create_bucket(ctx, s3, log_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, log_bucket))
    s3.put_bucket_ownership_controls(
        Bucket=log_bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]})

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-obs3-std-oac-"),
        "OriginAccessControlOriginType": "s3", "SigningBehavior": "always", "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac_if_present(cf, oac_id))

    def config(enabled: bool) -> dict:
        return {
            "CallerReference": ctx.unique_name("sim2real-obs3-std-"),
            "Comment": f"sim2real obs-cloudfront-3 standard logs enabled={enabled}",
            "Enabled": True,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "s3", "DomainName": f"{content_bucket}.s3.{ctx.region}.amazonaws.com",
                "S3OriginConfig": {"OriginAccessIdentity": ""}, "OriginAccessControlId": oac_id,
            }]},
            "DefaultCacheBehavior": {"TargetOriginId": "s3", "ViewerProtocolPolicy": "allow-all",
                                     "CachePolicyId": MANAGED_CACHING_OPTIMIZED},
            "Logging": {"Enabled": enabled, "IncludeCookies": False,
                        "Bucket": f"{log_bucket}.s3.amazonaws.com", "Prefix": LOG_PREFIX},
        }

    dists = {}
    for enabled in (True, False):
        d = cf.create_distribution(DistributionConfig=config(enabled))["Distribution"]
        ctx.on_cleanup(lambda i=d["Id"]: _release_distribution(cf, i))
        cf.tag_resource(Resource=d["ARN"], Tags={"Items": _TAGS})
        dists[enabled] = d
    on, off = dists[True], dists[False]

    s3.put_bucket_policy(Bucket=content_bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{content_bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": [on["ARN"], off["ARN"]]}},
        }],
    }))

    on_logging = cf.get_distribution_config(Id=on["Id"])["DistributionConfig"]["Logging"]
    assert on_logging == {"Enabled": True, "IncludeCookies": False,
                          "Bucket": f"{log_bucket}.s3.amazonaws.com", "Prefix": LOG_PREFIX}, (
        f"the enabled distribution must store the Logging block as sent, got {on_logging!r}")
    # Measured: CloudFront normalises a disabled Logging block, discarding Bucket and Prefix.
    off_logging = cf.get_distribution_config(Id=off["Id"])["DistributionConfig"]["Logging"]
    assert off_logging == {"Enabled": False, "IncludeCookies": False, "Bucket": "", "Prefix": ""}, (
        f"a disabled Logging block must be stored with Bucket and Prefix cleared, got {off_logging!r}")

    for d in (on, off):
        _wait_deployed(cf, d["Id"])

    # --- traffic: interleaved, Miss first, then repeat until the edge reports a Hit ------------
    agent = f"sim2real-{ctx.unique_name('ua-')}"
    served = {True: {}, False: {}}
    for attempt in range(12):
        for enabled, d in ((True, on), (False, off)):
            url, route_headers = ctx.endpoint_route(f"{d['DomainName']}/{key}")
            rid, result = _served(url, route_headers, agent, ctx.http_verify)
            served[enabled][rid] = result
        if attempt >= 1 and all("Hit" in s.values() for s in served.values()):
            break
        time.sleep(2)
    for enabled, seen in served.items():
        assert {"Miss", "Hit"} <= set(seen.values()), (
            f"distribution enabled={enabled} must serve a Miss then a Hit for the same object under "
            f"CachingOptimized; X-Cache results were {seen!r}")

    # --- barrier: wait for every enabled-side request id to land --------------------------------
    rid_i = DOCUMENTED_FIELDS.index("x-edge-request-id")

    def enabled_rows():
        files = _log_files(s3, log_bucket)
        return files, {r[rid_i]: r for k, t in files.items() if on["Id"] in k for r in _parse(t)[1]
                       if len(r) > rid_i}

    files, rows = _poll_until(enabled_rows, lambda fr: set(served[True]) <= set(fr[1]),
                              timeout_s=1800.0, interval_s=30.0,
                              description=f"standard-log rows for request ids {sorted(served[True])}")

    on_files = {k: t for k, t in files.items() if on["Id"] in k}
    assert all(k.startswith(LOG_PREFIX) for k in on_files), (
        f"every delivered object must sit under the configured prefix {LOG_PREFIX!r}, got {sorted(on_files)}")
    all_ids = []
    for k, text in on_files.items():
        fields, data = _parse(text)
        assert text.startswith("#Version: 1.0\n"), f"{k} must open with '#Version: 1.0', got {text[:40]!r}"
        assert fields == DOCUMENTED_FIELDS, (
            f"{k}: #Fields must be the documented {len(DOCUMENTED_FIELDS)}-field set in order, got {fields!r}")
        for row in data:
            assert len(row) == len(fields), (
                f"{k}: a data line must have one tab-separated column per #Fields name "
                f"({len(fields)}), got {len(row)}: {row!r}")
            all_ids.append(row[fields.index("x-edge-request-id")])
    assert len(all_ids) == len(set(all_ids)), (
        f"x-edge-request-id must be distinct per log line, got duplicates in {sorted(all_ids)}")

    ix = {name: i for i, name in enumerate(DOCUMENTED_FIELDS)}
    for rid, result in served[True].items():
        row = rows[rid]
        assert row[ix["x-edge-result-type"]] == result, (
            f"row {rid}: x-edge-result-type must equal what X-Cache told the viewer ({result!r}), "
            f"got {row[ix['x-edge-result-type']]!r}")
        assert (row[ix["cs-uri-stem"]], row[ix["sc-status"]], row[ix["cs-method"]]) == (f"/{key}", "200", "GET"), (
            f"row {rid} must describe GET /{key} -> 200, got {row!r}")
        assert row[ix["cs(User-Agent)"]] == agent, (
            f"row {rid} cs(User-Agent) must be this run's agent {agent!r}, got {row[ix['cs(User-Agent)']]!r}")
    logged_results = {rows[rid][ix["x-edge-result-type"]] for rid in served[True]}
    assert {"Hit", "Miss"} <= logged_results, (
        f"the log must carry one Hit line and one Miss line, got result types {sorted(logged_results)}")

    # --- the disabled control: same bucket, same prefix, same moment — nothing -----------------
    control_keys = sorted(k for k in files if off["Id"] in k)
    assert not control_keys, (
        f"a distribution with Logging.Enabled=false must deliver no object, but {control_keys} "
        f"landed after the enabled side's {len(served[True])} rows did")
    control_rows = sorted(rid for rid in served[False] if any(rid in t for t in files.values()))
    assert not control_rows, (
        f"no delivered log may mention the disabled distribution's request ids, found {control_rows}")

    # --- teardown of the slow chain, in the body (see _teardown_distributions) -----------------
    _teardown_distributions(cf, [on["Id"], off["Id"]])
    _retry_in_use(lambda: _delete_oac(cf, oac_id))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
