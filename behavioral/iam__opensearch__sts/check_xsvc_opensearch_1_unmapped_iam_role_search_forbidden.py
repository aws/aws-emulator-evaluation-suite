"""xsvc-opensearch-1-unmapped-iam-role-search-forbidden."""
from __future__ import annotations

import json
import socket
import ssl
import time
from urllib.parse import urlsplit

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-opensearch-1-unmapped-iam-role-search-forbidden"
GROUP = "overly-permissive"
SERVICES = ["iam", "opensearch", "sts"]

ERROR_TYPE = "security_exception"

ENGINE_VERSION = "OpenSearch_2.11"
MIN_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1,
                      "DedicatedMasterEnabled": False, "ZoneAwarenessEnabled": False}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
_SCENARIO = "xsvc-opensearch-1-unmapped-iam-role"


def _read_to_eof(sock):
    parts = []
    while True:
        block = sock.recv(65536)
        if not block:
            return b"".join(parts)
        parts.append(block)


def _dechunk(body):
    out = bytearray()
    pos = 0
    while True:
        nl = body.find(b"\r\n", pos)
        if nl < 0:
            raise AssertionError(f"{DATAPLANE_MARKER}: chunked response truncated at byte {pos}")
        size = int(body[pos:nl].split(b";")[0].strip(), 16)
        pos = nl + 2
        if size == 0:
            return bytes(out)
        out += body[pos:pos + size]
        pos += size + 2


def _tls(ctx):
    """The TLS context for the target: the system trust store, the target's CA bundle, or none."""
    verify = ctx.http_verify
    if verify is False:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _native_request(ctx, host, method, path, *, headers, body=None, timeout=120):
    """Speak the OpenSearch REST protocol on a TLS socket this function opens itself.

    The OpenSearch HTTP API is not a Smithy API, so framing and chunked decoding are done here.
    """
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
    for name, value in headers.items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    wire = ("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b"")
    url, _ = ctx.endpoint_route(host)
    target = urlsplit(url)
    secure = target.scheme == "https"
    try:
        raw = socket.create_connection(
            (target.hostname, target.port or (443 if secure else 80)), timeout=timeout)
    except OSError as exc:  # the endpoint the target published refused a connect
        raise AssertionError(f"{DATAPLANE_MARKER}: could not open a TLS socket to {host!r}: "
                             f"{type(exc).__name__}: {exc}") from exc
    try:
        sock = _tls(ctx).wrap_socket(raw, server_hostname=target.hostname) if secure else raw
        sock.settimeout(timeout)
        sock.sendall(wire)
        blob = _read_to_eof(sock)
    except OSError as exc:  # same classification, one layer in
        raise AssertionError(f"{DATAPLANE_MARKER}: {method} {path} to {host!r} did not complete: "
                             f"{type(exc).__name__}: {exc}") from exc
    finally:
        try:
            raw.close()
        except OSError:
            pass
    split = blob.find(b"\r\n\r\n")
    if split < 0:
        raise AssertionError(f"{DATAPLANE_MARKER}: no HTTP header terminator for {method} {path}: "
                             f"{blob[:200]!r}")
    head = blob[:split].decode("iso-8859-1")
    content = blob[split + 4:]
    fields = head.split("\r\n")[0].split(" ", 2)
    if len(fields) < 2 or not fields[1].isdigit():
        raise AssertionError(f"{DATAPLANE_MARKER}: unparseable status line {head[:80]!r}")
    seen = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            seen[k.strip().lower()] = v.strip()
    if seen.get("transfer-encoding", "").lower() == "chunked":
        content = _dechunk(content)
    text = content.decode("utf-8", errors="replace")
    try:
        return int(fields[1]), (json.loads(text) if text.strip() else {})
    except ValueError:
        return int(fields[1]), {"raw": text}


def _signed(ctx, host, creds, method, path, body=None):
    """SigV4-sign (service `es`) an OpenSearch REST call as `creds`, then send it ourselves.

    Paths here never carry a wildcard or a reserved character, so the canonical URI botocore signs
    is byte-identical to the request line we send.
    """
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = AWSRequest(method=method, url=f"https://{host}{path}", data=data or b"",
                     headers=headers)
    SigV4Auth(creds, "es", ctx.region).add_auth(req)
    return _native_request(ctx, host, method, path, headers=dict(req.headers.items()), body=data)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_access_denied(fn, *, what, timeout_s=120.0, ctx=None):
    """IAM propagation exposes no condition to poll; the bounded retry at first use IS the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "AccessDenied" or time.monotonic() >= deadline:
                if code == "AccessDenied" and ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"{what} past IAM propagation: the run budget ended first; not graded") from exc
                raise AssertionError(f"{what} failed with {code!r}: "
                                     f"{exc.response.get('Error', {}).get('Message')!r}") from exc
        time.sleep(2.0)


def _make_role(ctx, name, trust, policy):
    iam = ctx.client("iam")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Description="sim2real xsvc-opensearch-1",
                          Tags=[{"Key": "sim2real", "Value": _SCENARIO}])["Role"]["Arn"]

    def _drop():
        try:
            iam.delete_role_policy(RoleName=name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=name)
    ctx.on_cleanup(_drop)
    iam.put_role_policy(RoleName=name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return arn


def _assume(ctx, role_arn, session):
    out = _retry_access_denied(
        lambda: ctx.client("sts").assume_role(RoleArn=role_arn, RoleSessionName=session,
                                              DurationSeconds=3600),
        what=f"AssumeRole {role_arn}", timeout_s=_budget_s(ctx, 120.0), ctx=ctx)["Credentials"]
    return Credentials(out["AccessKeyId"], out["SecretAccessKey"], out["SessionToken"])


def _delete_domain_quietly(osc, name):
    try:
        osc.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_iam_admin_domain(ctx, account, admin_arn):
    """Cheapest legal FGAC domain whose admin user is an IAM ROLE ARN (no internal user DB).

    The resource policy delegates to IAM (principal = this account's root), so every principal
    still needs an identity policy allowing es:ESHttp*, and FGAC then decides on top of that.
    """
    osc = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-x1-")[:28]
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, name))
    kwargs = dict(
        DomainName=name, EngineVersion=ENGINE_VERSION, ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS), EncryptionAtRestOptions={"Enabled": True},
        NodeToNodeEncryptionOptions={"Enabled": True},
        DomainEndpointOptions={"EnforceHTTPS": True,
                               "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
        AdvancedSecurityOptions={"Enabled": True, "InternalUserDatabaseEnabled": False,
                                 "MasterUserOptions": {"MasterUserARN": admin_arn}},
        AccessPolicies=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account}:domain/{name}/*"}]}),
        TagList=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    for attempt in range(12):
        if attempt:
            time.sleep(6.0 * attempt)
        try:
            osc.create_domain(**kwargs)
            return name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_domain(ctx, name, timeout_s=1800.0):
    osc = ctx.client("opensearch")
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = {}
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"], last["ARN"]
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {name} publishing an endpoint: the run budget ended first; not graded")
    raise AssertionError(f"domain {name} published no endpoint within {budget}s "
                         f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})")


def _wait_admin(ctx, host, creds, timeout_s=420.0):
    """Processing=False does not mean the security plugin accepts the IAM admin role yet."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _signed(ctx, host, creds, "GET", "/_cluster/health")
        if status == 200:
            return
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError("the IAM admin role getting 200 on /_cluster/health: the run budget ended first; not graded")
    raise AssertionError(f"the IAM admin role never got 200 on /_cluster/health within {timeout_s}s "
                         f"(last HTTP {status!r}: {body!r})")


def _error_type(payload):
    """OpenSearch engine errors are {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    return str(error.get("type")) if isinstance(error, dict) else None


def _poll_200(ctx, host, creds, method, path, body=None, *, what, timeout_s=300.0):
    """Wait for an authorised call to succeed; role-mapping and IAM propagation are eventually
    consistent and a not-yet-effective grant answers 403 like a real denial."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status, payload = None, {}
    while time.monotonic() < deadline:
        status, payload = _signed(ctx, host, creds, method, path, body)
        if status == 200:
            return payload
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"{what} returning 200: the run budget ended first; not graded")
    raise AssertionError(f"{what} never returned 200 within {timeout_s}s "
                         f"(last HTTP {status!r}: {payload!r})")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c7",
)
def run(ctx) -> None:
    """With FGAC and identical IAM grants, the FGAC-mapped role's _search reads the document while
    the unmapped role gets 403 security_exception naming the refused action and leaking no content.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html
    """
    account = ctx.client("sts").get_caller_identity()["Account"]
    root_trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
        "Action": "sts:AssumeRole"}]}
    domains = f"arn:aws:es:{ctx.region}:{account}:domain/sim2real-x1-*/*"

    admin_arn = _make_role(ctx, ctx.unique_name("sim2real-xsvc-osm-"), root_trust, {
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Action": "es:ESHttp*", "Resource": domains}]})
    domain = _create_iam_admin_domain(ctx, account, admin_arn)
    reader_policy = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["es:ESHttpGet", "es:ESHttpPost"], "Resource": domains}]}
    reader_arn = _make_role(ctx, ctx.unique_name("sim2real-xsvc-osr-"), root_trust,
                            reader_policy)
    # The same IAM grant, byte for byte: what differs is ONLY the FGAC mapping.
    outsider_arn = _make_role(ctx, ctx.unique_name("sim2real-xsvc-oso-"), root_trust,
                              reader_policy)

    host, _ = _wait_domain(ctx, domain)
    admin = _assume(ctx, admin_arn, "sim2real-admin")
    _wait_admin(ctx, host, admin)

    index = "sim2real-fgac-secret"
    status, body = _signed(ctx, host, admin, "PUT", f"/{index}",
                           {"settings": {"number_of_shards": 1, "number_of_replicas": 0}})
    assert status == 200, f"creating {index!r} returned HTTP {status!r}: {body!r}"
    status, body = _signed(ctx, host, admin, "PUT", f"/{index}/_doc/1?refresh=true",
                           {"marker": "secret-doc"})
    assert status == 201, f"indexing returned HTTP {status!r}: {body!r}"

    status, body = _signed(ctx, host, admin, "PUT",
                           "/_plugins/_security/api/roles/sim2real_reader", {
                               "cluster_permissions": ["cluster_composite_ops_ro"],
                               "index_permissions": [{"index_patterns": [index],
                                                      "allowed_actions": ["read", "search"]}]})
    assert status in (200, 201), f"FGAC role PUT returned HTTP {status!r}: {body!r}"
    status, body = _signed(ctx, host, admin, "PUT",
                           "/_plugins/_security/api/rolesmapping/sim2real_reader",
                           {"backend_roles": [reader_arn]})
    assert status in (200, 201), f"FGAC role mapping PUT returned HTTP {status!r}: {body!r}"

    reader = _assume(ctx, reader_arn, "sim2real-reader")
    outsider = _assume(ctx, outsider_arn, "sim2real-outsider")
    query = {"query": {"match_all": {}}}

    # Positive control (and propagation barrier): the mapped role reads the document.
    hits = _poll_200(ctx, host, reader, "POST", f"/{index}/_search", query,
                     what="the mapped role's signed _search")
    markers = [h["_source"].get("marker") for h in hits["hits"]["hits"]]
    assert markers == ["secret-doc"], f"the mapped role read {markers!r}, expected ['secret-doc']"

    # authinfo succeeding proves IAM admits the outsider, so the later 403 is FGAC, not IAM
    # (an IAM denial would say "not authorized to perform", not security_exception).
    info = _poll_200(ctx, host, outsider, "GET", "/_plugins/_security/authinfo",
                     what="the unmapped role's authinfo (IAM propagation barrier)")
    print("OBSERVED outsider authinfo:", info)
    assert outsider_arn in info.get("backend_roles", []), (
        f"authinfo did not resolve the outsider's backend role to {outsider_arn!r}: {info!r}")

    # The one thing that differs: no FGAC mapping.
    status, denied = _signed(ctx, host, outsider, "POST", f"/{index}/_search", query)
    print("OBSERVED outsider _search:", status, denied)
    assert status == 403, f"the unmapped role got HTTP {status!r}, expected 403: {denied!r}"
    assert _error_type(denied) == ERROR_TYPE, (
        f"expected error.type {ERROR_TYPE!r}, got {_error_type(denied)!r}: {denied!r}")
    # The security plugin names the refused action and the resolved user; the user stanza is
    # the one authinfo reported for this same principal.
    want_search = f"no permissions for [indices:data/read/search] and {info['user']}"
    assert denied["error"]["reason"] == want_search, (
        f"refusal reason differs: {denied['error']['reason']!r} != {want_search!r}")
    assert "secret-doc" not in json.dumps(denied), f"the refusal leaked content: {denied!r}"
    status, denied_get = _signed(ctx, host, outsider, "GET", f"/{index}/_doc/1")
    assert status == 403, f"a direct GET by the unmapped role returned HTTP {status!r}: {denied_get!r}"
    assert _error_type(denied_get) == ERROR_TYPE, (
        f"direct GET refusal is {_error_type(denied_get)!r}, expected {ERROR_TYPE!r}: {denied_get!r}")
    want_get = f"no permissions for [indices:data/read/get] and {info['user']}"
    assert denied_get["error"]["reason"] == want_get, (
        f"direct GET refusal reason differs: {denied_get['error']['reason']!r} != {want_get!r}")

    # And the mapped role is still served after the denial: the 403 is per-principal, not a
    # domain-wide state.
    status, again = _signed(ctx, host, reader, "POST", f"/{index}/_search", query)
    assert status == 200, f"the mapped role's re-read returned HTTP {status!r}: {again!r}"
    assert again["hits"]["total"]["value"] == 1, f"the mapped role's re-read: {again!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
