"""deep-cloudfront-2-cf-edge-enforce-signed-url-source-ip-denied."""
from __future__ import annotations

import base64
import io
import ipaddress
import json
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile

import requests
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from behavioral_harness import tags

CHECK = "deep-cloudfront-2-cf-edge-enforce-signed-url-source-ip-denied"
GROUP = "security"
SERVICES = ["cloudfront", "lambda"]

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

_STABLE_N = 3

_FUNCTION_SOURCE = '''\
import json
import os


def handler(event, context):
    headers = event.get("headers") or {}
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "marker": os.environ["SIM2REAL_MARKER"],
            "path": event.get("rawPath", ""),
            "viewer_address": headers.get("cloudfront-viewer-address"),
            "header_names": sorted(headers),
        }),
    }
'''


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition",
                ctx=None):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=1.0,
                                ctx=None) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed", ctx=ctx)
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id, timeout_s=1200.0) -> None:
    """Disable, wait for that change to deploy, then delete (CloudFront refuses an enabled delete).
    Called in the body on the success path and registered as the ctx.on_cleanup net for a
    failing run; a no-op once the distribution is gone.
    """
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, timeout_s=timeout_s)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _teardown_in_budget(cf, dist_id, ctx) -> None:
    """Delete the distribution in the body on the success path, within what is left of the
    check's time. A failed delete raises; on a failing run the registered net deletes it."""
    _disable_and_delete_distribution(cf, dist_id, timeout_s=_budget_s(ctx, 1200.0))


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _reap_log_group(logs, name: str, *, window_s: float = 10.0) -> None:
    """Delete a Lambda log group in a loop: a late flush can recreate it after one delete."""
    deadline = time.monotonic() + window_s
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise RuntimeError(f"log group {name}: {exc}") from exc
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
    if any(g["logGroupName"] == name for g in groups):
        raise RuntimeError(f"log group {name} reappeared after the reap window")


def _zip_source(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buf.getvalue()


def _managed_cache_policy_id(cf, name: str) -> str:
    """Resolve a managed cache policy id from the TARGET's own catalogue, not a constant."""
    marker = None
    while True:
        kwargs = {"Type": "managed", "MaxItems": "100"}
        if marker is not None:
            kwargs["Marker"] = marker
        page = cf.list_cache_policies(**kwargs)["CachePolicyList"]
        for item in page.get("Items", []):
            if item["CachePolicy"]["CachePolicyConfig"]["Name"] == name:
                return item["CachePolicy"]["Id"]
        marker = page.get("NextMarker")
        if marker is None:
            raise AssertionError(f"the managed cache policy {name!r} is not in the target's catalogue")


def _cf_b64(raw: bytes) -> str:
    """CloudFront's own URL-safe base64 alphabet: '+'->'-', '='->'_', '/'->'~'."""
    return base64.b64encode(raw).decode().replace("+", "-").replace("=", "_").replace("/", "~")


def _signed_url(url: str, resource: str, source_cidr: str, expires: int, private_key,
                key_id: str) -> str:
    """A CUSTOM-policy signed URL: RSA-SHA1 over the exact policy bytes that are sent."""
    policy = json.dumps({"Statement": [{
        "Resource": resource,
        "Condition": {"DateLessThan": {"AWS:EpochTime": expires},
                      "IpAddress": {"AWS:SourceIp": source_cidr}},
    }]}, separators=(",", ":")).encode()
    signature = private_key.sign(policy, padding.PKCS1v15(), hashes.SHA1())
    return (f"{url}?Policy={_cf_b64(policy)}&Signature={_cf_b64(signature)}"
            f"&Key-Pair-Id={key_id}")


def _xml_code(text: str) -> str:
    """The CloudFront error document's Code element, or '' when the body is not that document."""
    try:
        return ET.fromstring(text).findtext("Code") or ""
    except ET.ParseError:
        return ""


def _new_public_key(ctx, cf, label: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    key_id = cf.create_public_key(PublicKeyConfig={
        "CallerReference": ctx.unique_name(f"sim2real-cfsig-pk{label}-"),
        "Name": ctx.unique_name(f"sim2real-cfsig-pk{label}-"),
        "EncodedKey": pem,
        "Comment": f"sim2real signed URL key {label}",
    })["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_public_key, cf.delete_public_key, key_id))
    return private_key, key_id


def _get(session, url: str):
    try:
        return session.get(url, timeout=20)
    except requests.RequestException as exc:  # transport only, during edge propagation
        return exc


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Signed URL pinned to the discovered viewer IP admits; foreign /24 and a rotated-out key 403."""
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    marker = ctx.unique_name("sim2real-cfsig-marker-")

    role_name = ctx.unique_name("sim2real-behav-cfsig-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real echo origin behind a signed-URL CloudFront distribution",
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    function_name = ctx.unique_name("sim2real-behav-cfsig-fn-")
    # Before the function exists, so LIFO reaps after delete_function. The role grants no logs
    # permissions, so no group is expected; this is the net if one appears anyway.
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{function_name}"))

    def create_function():
        try:
            return lam.create_function(
                FunctionName=function_name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": _zip_source(_FUNCTION_SOURCE)},
                Timeout=10, Environment={"Variables": {"SIM2REAL_MARKER": marker}},
                Tags={t["Key"]: t["Value"] for t in _TAG_SET},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            return None  # the freshly created role has not propagated yet

    created = _poll_until(create_function, lambda r: r is not None, timeout_s=_budget_s(ctx, 180.0), interval_s=2.0,
                          description=f"CreateFunction to accept the freshly created role {role_name}",
                          ctx=ctx)
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))
    assert created["FunctionArn"].split(":")[4] == account, (
        f"expected the function in the calling account {account}, got {created['FunctionArn']!r}"
    )
    _poll_until(lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
                lambda state: state == "Active", timeout_s=_budget_s(ctx, 180.0), interval_s=1.0,
                description=f"lambda function {function_name} to become Active", ctx=ctx)
    function_url = lam.create_function_url_config(
        FunctionName=function_name, AuthType="AWS_IAM")["FunctionUrl"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function_url_config(
        FunctionName=function_name))
    origin_host = urllib.parse.urlparse(function_url).netloc
    assert urllib.parse.urlparse(function_url).scheme == "https" and origin_host, (
        f"CreateFunctionUrlConfig must return an absolute https URL, got {function_url!r}"
    )

    key_a, key_a_id = _new_public_key(ctx, cf, "a")
    key_b, key_b_id = _new_public_key(ctx, cf, "b")
    kg_name = ctx.unique_name("sim2real-cfsig-kg-")
    kg_id = cf.create_key_group(KeyGroupConfig={
        "Name": kg_name, "Items": [key_a_id, key_b_id], "Comment": "sim2real two trusted signers",
    })["KeyGroup"]["Id"]
    # After both public keys' cleanups: LIFO deletes the group first (a member key cannot be deleted).
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_key_group, cf.delete_key_group, kg_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfsig-oac-"),
        "OriginAccessControlOriginType": "lambda",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))
    orp_id = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": ctx.unique_name("sim2real-cfsig-orp-"),
        "Comment": "sim2real forward viewer address to the echo origin",
        "HeadersConfig": {"HeaderBehavior": "whitelist",
                          "Headers": {"Quantity": 1, "Items": ["CloudFront-Viewer-Address"]}},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    })["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_request_policy,
                                             cf.delete_origin_request_policy, orp_id))
    caching_disabled = _managed_cache_policy_id(cf, "Managed-CachingDisabled")

    def behavior(extra: dict) -> dict:
        return {"TargetOriginId": "echo", "ViewerProtocolPolicy": "https-only",
                "CachePolicyId": caching_disabled, "OriginRequestPolicyId": orp_id, **extra}

    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-behav-cfsig-cr-"),
            "Comment": "sim2real signed URL source-ip + key rotation",
            "Enabled": True,
            # With IPv6 on, a dual-stack viewer can flip address families between requests, and a
            # policy pinned to the first address would 403 the positive leg spuriously.
            "IsIPV6Enabled": False,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "echo",
                "DomainName": origin_host,
                "CustomOriginConfig": {
                    "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    "OriginReadTimeout": 30, "OriginKeepaliveTimeout": 5,
                },
                "OriginAccessControlId": oac_id,
            }]},
            "DefaultCacheBehavior": behavior({
                "TrustedKeyGroups": {"Enabled": True, "Quantity": 1, "Items": [kg_id]}}),
            "CacheBehaviors": {"Quantity": 1, "Items": [
                {"PathPattern": "/whoami*", **behavior({})}]},
        },
        "Tags": {"Items": _TAG_SET},
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    lam.add_permission(FunctionName=function_name, StatementId="sim2real-cf-oac-url",
                       Action="lambda:InvokeFunctionUrl", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist["ARN"], FunctionUrlAuthType="AWS_IAM")
    lam.add_permission(FunctionName=function_name, StatementId="sim2real-cf-oac-fn",
                       Action="lambda:InvokeFunction", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist["ARN"])
    edge, route_headers = ctx.endpoint_route(dist["DomainName"])
    session = requests.Session()
    session.headers.update(route_headers)

    _wait_distribution_deployed(cf, dist_id, timeout_s=_budget_s(ctx, 1200.0), ctx=ctx)

    # Discover the viewer address CloudFront sees for this caller (unsigned behavior).
    try:
        who = _poll_until(lambda: _get(session, f"{edge}/whoami"),
                          lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                          timeout_s=_budget_s(ctx, 300.0), interval_s=1.0,
                          description="200 from the unsigned /whoami behavior", ctx=ctx)
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    who_payload = json.loads(who.text)
    assert who_payload["marker"] == marker and "x-amz-cf-id" in who_payload["header_names"], (
        f"/whoami must be answered by this run's origin through CloudFront: {who_payload!r}"
    )
    viewer_address = who_payload["viewer_address"]
    assert isinstance(viewer_address, str) and ":" in viewer_address, (
        f"CloudFront-Viewer-Address must be '<ip>:<port>', got {viewer_address!r}"
    )
    viewer_ip = ipaddress.ip_address(viewer_address.rsplit(":", 1)[0])
    assert viewer_ip.version == 4, (
        f"IsIPV6Enabled=False, so the edge must see an IPv4 viewer, got {viewer_ip!r}"
    )
    own_cidr = f"{viewer_ip}/32"
    # The caller cannot change its egress address, so the foreign request is a policy for a
    # /24 that cannot hold the viewer (same /16, third octet + 1 mod 256), sent from the real
    # address.
    raw = int(viewer_ip)
    third = (raw >> 8) & 0xFF
    foreign_net = ipaddress.ip_network(((raw & 0xFFFF0000) | (((third + 1) % 256) << 8), 24))
    assert viewer_ip not in foreign_net, f"{foreign_net} must not contain {viewer_ip}"

    # The policy names the published URL; each signed URL is then routed like any other request.
    published = f"{urllib.parse.urlsplit(edge).scheme}://{dist['DomainName']}"
    resource = f"{published}/secure/*"
    expires = int(time.time()) + 1800

    def signed(path: str, cidr: str, pk, kid: str) -> str:
        return ctx.endpoint_route(_signed_url(f"{published}{path}", resource, cidr, expires, pk, kid))[0]

    # BEAT a — key A, policy pinned to the discovered address: admitted, served by the origin.
    url_a = signed("/secure/a", own_cidr, key_a, key_a_id)
    try:
        admitted = _poll_until(lambda: _get(session, url_a),
                               lambda r: isinstance(r, requests.Response) and r.status_code == 200,
                               timeout_s=_budget_s(ctx, 240.0), interval_s=1.0,
                               description=f"200 for the key-A URL signed for {own_cidr}",
                               ctx=ctx)
    except AssertionError as exc:
        last = _get(session, url_a)
        detail = (f"{last.status_code} {last.text[:300]!r}" if isinstance(last, requests.Response)
                  else repr(last))
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc} | last: {detail}") from exc
    pa = json.loads(admitted.text)
    assert pa["marker"] == marker and pa["path"] == "/secure/a", (
        f"the admitted signed URL must be served by this run's origin at /secure/a: {pa!r}"
    )

    # BEAT b — same key, same resource, policy for a /24 that excludes the viewer: refused.
    foreign = session.get(signed("/secure/a", str(foreign_net), key_a, key_a_id), timeout=20)
    assert foreign.status_code == 403, (
        f"a policy whose AWS:SourceIp is {foreign_net} (viewer is {viewer_ip}) must be refused: "
        f"expected 403, got {foreign.status_code} / {foreign.text[:300]!r}"
    )
    foreign_code = _xml_code(foreign.text)
    assert foreign_code == "AccessDenied", (
        f"expected CloudFront's error document to name AccessDenied for the source-ip mismatch, "
        f"got {foreign_code!r} / {foreign.text[:300]!r}"
    )
    assert marker not in foreign.text, f"the refusal leaked origin bytes: {foreign.text[:300]!r}"

    # BEAT c — both trusted signers admit.
    url_b = signed("/secure/b", own_cidr, key_b, key_b_id)
    rb = session.get(url_b, timeout=20)
    assert rb.status_code == 200, (
        f"key B is in the trusted key group, so its signature must be admitted: got "
        f"{rb.status_code} / {rb.text[:300]!r}"
    )
    assert json.loads(rb.text)["path"] == "/secure/b", f"unexpected origin echo {rb.text[:200]!r}"
    ra = session.get(url_a, timeout=20)
    assert ra.status_code == 200, f"key A must still be admitted: {ra.status_code} {ra.text[:200]!r}"

    # BEAT d — rotate key B out of the group.
    kg = cf.get_key_group(Id=kg_id)
    cf.update_key_group(Id=kg_id, IfMatch=kg["ETag"], KeyGroupConfig={
        "Name": kg_name, "Items": [key_a_id], "Comment": "sim2real key B rotated out"})
    stored = cf.get_key_group(Id=kg_id)["KeyGroup"]["KeyGroupConfig"]["Items"]
    assert stored == [key_a_id], f"expected the key group to hold only key A, got {stored!r}"

    streak: list = []

    def b_probe():
        r = _get(session, url_b)
        if isinstance(r, requests.Response) and r.status_code == 403:
            streak.append(r)
        else:
            streak.clear()
        return r

    try:
        _poll_until(b_probe, lambda _r: len(streak) >= _STABLE_N, timeout_s=_budget_s(ctx, 900.0),
                    interval_s=2.0, ctx=ctx,
                    description=f"{_STABLE_N} consecutive 403s for the rotated-out key B")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    revoked = streak[-1]
    revoked_code = _xml_code(revoked.text)
    # A key no longer in any trusted group is UNKNOWN to the behavior: CloudFront names it
    # InvalidKey ("Unknown Key"), a different code from the source-ip AccessDenied of beat b — a
    # target answering AccessDenied here is not consulting the key group membership at all.
    assert revoked_code == "InvalidKey", (
        f"expected CloudFront's error document to name InvalidKey for a key rotated out of the "
        f"trusted key group, got {revoked_code!r} / {revoked.text[:300]!r}"
    )
    assert marker not in revoked.text, f"the refusal leaked origin bytes: {revoked.text[:300]!r}"
    still = session.get(url_a, timeout=20)
    assert still.status_code == 200 and json.loads(still.text)["marker"] == marker, (
        f"key A remains trusted, so its URL must still be served by the origin: "
        f"{still.status_code} / {still.text[:200]!r}"
    )
    _teardown_in_budget(cf, dist_id, ctx)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
