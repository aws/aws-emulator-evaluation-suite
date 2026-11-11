"""osm-integer-field-mapping-conflict-rejected."""
from __future__ import annotations

import json
import random
import socket
import ssl
import urllib.parse
import time

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "osm-integer-field-mapping-conflict-rejected"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== self-contained protocol helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a real
# cost-leak class, so this provisions the cheapest legal cluster and registers teardown BEFORE
# the create call.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# A data-plane FAIL marker: a detail string carrying it scores a domain endpoint the target
# published and then failed to answer on as a real fidelity failure, never as an environment gap.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted.

    Anything other than "already gone" is re-raised: ``ctx.on_cleanup`` swallows exceptions, so a
    silently-failed delete leaks a 24x7 cluster while the check still passes.
    """
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _read_to_eof(sock) -> bytes:
    parts = []
    while True:
        block = sock.recv(65536)
        if not block:
            return b"".join(parts)
        parts.append(block)


def _dechunk(body: bytes) -> bytes:
    """Undo ``Transfer-Encoding: chunked``.

    OpenSearch answers a search with chunked framing, so a client that owns its own socket owns
    this too -- there is no library underneath to do it.
    """
    out = bytearray()
    pos = 0
    while True:
        nl = body.find(b"\r\n", pos)
        if nl < 0:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: chunked response truncated at byte {pos}: "
                f"{body[pos:pos + 48]!r}")
        size_field = body[pos:nl].split(b";")[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError as exc:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: malformed chunk size {size_field!r}") from exc
        pos = nl + 2
        if size == 0:
            return bytes(out)
        out += body[pos:pos + size]
        pos += size + 2


def _native_request(ctx, host, method, path, *, headers=None, body=None, timeout=120):
    """Speak the OpenSearch REST protocol on a TLS socket this function opens itself.

    `dp:native`: the OpenSearch HTTP API is not an AWS Smithy API, and nothing between this
    function and the cluster is an AWS SDK -- the request line, the headers, the framing and the
    chunked decoding are all ours. That is deliberate rather than ornamental: a target may serve a
    well-formed JSON body through a helpful HTTP library and still not be an OpenSearch node, so
    the protocol itself must be graded directly, with no third-party client dependency.
    """
    payload = body if body is not None else b""
    # `host` is the domain's base URL from ctx.endpoint_url: dial its own scheme, host and port.
    target = urllib.parse.urlsplit(host)
    secure = target.scheme == "https"
    port = target.port or (443 if secure else 80)
    lines = [f"{method} {path} HTTP/1.1", f"Host: {target.netloc}", "Connection: close"]
    for name, value in (headers or {}).items():
        if name.lower() != "host":
            lines.append(f"{name}: {value}")
    if body is not None:
        lines.append(f"Content-Length: {len(payload)}")
    wire = ("\r\n".join(lines) + "\r\n\r\n").encode() + payload

    verify = ctx.http_verify
    if verify is False:
        tls = ssl._create_unverified_context()
    else:
        tls = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    try:
        raw = socket.create_connection((target.hostname, port), timeout=timeout)
    except OSError as exc:  # the endpoint the target published did not accept a TCP connection
        # A transport failure is not data a caller can assert on, and socket wording ("Connection
        # refused", "timed out") reads as a local network problem. The host here was
        # published by the target itself, so failing to answer on it is the target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: could not open a TLS socket to the domain endpoint "
            f"{host!r}: {type(exc).__name__}: {exc}") from exc
    try:
        sock = tls.wrap_socket(raw, server_hostname=target.hostname) if secure else raw
        sock.settimeout(timeout)
        sock.sendall(wire)
        blob = _read_to_eof(sock)
    except OSError as exc:  # same classification, one layer in (TLS / read)
        raise AssertionError(
            f"{DATAPLANE_MARKER}: {method} {path} over a TLS socket to {host!r} did not complete: "
            f"{type(exc).__name__}: {exc}") from exc
    finally:
        try:
            raw.close()
        except OSError:
            pass

    split = blob.find(b"\r\n\r\n")
    if split < 0:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: no HTTP header terminator in the {len(blob)} bytes returned for "
            f"{method} {path}: {blob[:200]!r}")
    head = blob[:split].decode("iso-8859-1")
    content = blob[split + 4:]
    status_line = head.split("\r\n")[0]
    fields = status_line.split(" ", 2)
    if len(fields) < 2 or not fields[1].isdigit():
        raise AssertionError(
            f"{DATAPLANE_MARKER}: unparseable HTTP status line {status_line!r} for {method} {path}")
    status = int(fields[1])
    seen = {}
    for line in head.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            seen[key.strip().lower()] = value.strip()
    if seen.get("transfer-encoding", "").lower() == "chunked":
        content = _dechunk(content)
    text = content.decode("utf-8", errors="replace")
    try:
        return status, (json.loads(text) if text.strip() else {})
    except ValueError:
        return status, {"raw": text}


def _signed(ctx, host, method, path, *, body=None):
    """SigV4-sign ('es') then send over our own socket.

    Signs with the credentials ctx wires for this account, never boto3's ambient chain: signing as
    the wrong principal makes the domain's account-scoped policy 403 the request, which reads
    exactly like a fidelity failure. Only `Authorization` and `X-Amz-Date` are signed headers;
    `Host` is signed by value and sent verbatim by `_native_request`.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=f"{host}{path}", data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    return _native_request(ctx, host, method, path, headers=dict(aws_req.headers), body=data)


def _account_access_policy(ctx, domain_name: str) -> str:
    """Resource-based policy letting this account's principals use the data plane."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
        }],
    })


def _create_min_domain(ctx, *, scenario: str, **overrides) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-osm-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never leak a
    # 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so a tag-based cleanup can find the domain if teardown is
        # interrupted.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter before the first attempt, then
    # back off on throttling.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0
                   else 6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1500.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # Concurrent domain polls in one account hit DescribeDomain's rate limit: poll again.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _wait_data_plane_ready(ctx, host: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has the
    access policy yet; signed requests can 403 for a while. Poll a cheap GET until it clears.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed(ctx, host, "GET", "/")
        if status != 403:
            return
        time.sleep(2)
    raise AssertionError(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status!r})")


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}.

    Structural and single-valued, never an alternation: one field is read rather than several
    codes accepted.
    """
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return sorted(h["_id"] for h in result["hits"]["hits"])


# ===== end protocol helpers =====

_SCENARIO = "osm-mapping-conflict"
_INDEX = "sim2real-osm-mapping"


def _mapped_type(ctx, host: str, field: str):
    """The type the cluster reports for `field`, read structurally out of the mapping."""
    status, mapping = _signed(ctx, host, "GET", f"/{_INDEX}/_mapping")
    assert status == 200, f"_mapping read returned HTTP {status!r}, expected 200: {mapping!r}"
    props = mapping.get(_INDEX, {}).get("mappings", {}).get("properties", {})
    return props.get(field, {}).get("type")


def _error_reason(payload) -> str:
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("reason") or "")
    return ""


def _ids_query(ctx, host: str, doc_id: str) -> dict:
    status, result = _signed(ctx, host, "POST", f"/{_INDEX}/_search",
                             body={"track_total_hits": True,
                                   "query": {"ids": {"values": [doc_id]}}})
    assert status == 200, f"ids-query _search returned HTTP {status!r}, expected 200: {result!r}"
    return result


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Indexing a non-numeric string into an `integer`-mapped field is refused HTTP 400
    `mapper_parsing_exception` naming the field and its type; the document stays absent on two
    independent reads, the mapping is unchanged, and the index still takes a conforming document."""
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    host = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, host)

    status, created = _signed(ctx, host, "PUT", f"/{_INDEX}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"title": {"type": "keyword"},
                                    "views": {"type": "integer"}}}})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed(ctx, host, "DELETE", f"/{_INDEX}"))
    assert created.get("acknowledged") is True, (
        f"index creation reported acknowledged={created.get('acknowledged')!r}, expected True: "
        f"{created!r}")
    declared = _mapped_type(ctx, host, "views")
    assert declared == "integer", (
        f"the cluster mapped 'views' as {declared!r}, expected 'integer' -- without that mapping "
        f"in force the rejection below would prove nothing")

    # POSITIVE CONTROL, before anything is broken: the identical document shape with a legal value.
    status, ok = _signed(ctx, host, "PUT", f"/{_INDEX}/_doc/control",
                         body={"title": "control", "views": 7})
    assert status == 201, (
        f"the control document was rejected with HTTP {status!r}, expected 201: {ok!r}")
    assert ok.get("result") == "created", (
        f"the control document reported result {ok.get('result')!r}, expected 'created': {ok!r}")

    # THE ONE BROKEN THING: a string that is not a number, into the integer field.
    status, refused = _signed(ctx, host, "PUT", f"/{_INDEX}/_doc/conflict",
                              body={"title": "conflict", "views": "not-a-number"})
    assert status == 400, (
        f"indexing a non-numeric string into an integer field returned HTTP {status!r}, expected "
        f"400 -- accepting it is over-permissiveness in the most damaging place, because the "
        f"customer's ingest then fails only in production: {refused!r}")
    assert _error_type(refused) == "mapper_parsing_exception", (
        f"the refusal reports error.type {_error_type(refused)!r}, expected "
        f"'mapper_parsing_exception': {refused!r}")
    reason = _error_reason(refused)
    assert "failed to parse field" in reason, (
        f"the refusal reason {reason!r} does not say the field failed to parse -- a refusal that "
        f"does not say what went wrong is indistinguishable from an unrelated 400")
    assert "[views]" in reason, (
        f"the refusal reason {reason!r} does not name the offending field 'views'")
    assert "[integer]" in reason, (
        f"the refusal reason {reason!r} does not name the mapped type 'integer' it could not "
        f"parse into")

    # EFFECT ABSENT, on two independent reads. The refresh is what makes the search read
    # meaningful: an unrefreshed index answers zero hits for a document that IS there.
    status, refreshed = _signed(ctx, host, "POST", f"/{_INDEX}/_refresh")
    assert status == 200, f"_refresh returned HTTP {status!r}, expected 200: {refreshed!r}"
    status, gone = _signed(ctx, host, "GET", f"/{_INDEX}/_doc/conflict")
    assert status == 404, (
        f"the rejected document is retrievable: GET by id returned HTTP {status!r}, expected 404: "
        f"{gone!r}")
    assert gone.get("found") is False, (
        f"GET by id reports found={gone.get('found')!r} for the rejected document, expected "
        f"False: {gone!r}")
    found = _ids_query(ctx, host, "conflict")
    assert _total(found) == 0, (
        f"an ids query for the rejected document reports {_total(found)!r} hits, expected 0: "
        f"hits={found.get('hits')!r}")

    # And the mapping was not widened to accommodate the value it refused.
    still = _mapped_type(ctx, host, "views")
    assert still == "integer", (
        f"the rejected write mutated the mapping: 'views' is now {still!r}, expected 'integer' -- "
        f"a target that learns the type from a refused document has silently changed the schema")
    status, mapping = _signed(ctx, host, "GET", f"/{_INDEX}/_mapping")
    assert status == 200, f"_mapping read returned HTTP {status!r}: {mapping!r}"
    fields = sorted(mapping[_INDEX]["mappings"]["properties"])
    assert fields == ["title", "views"], (
        f"the mapping now declares {fields!r}, expected ['title', 'views'] -- the refused document "
        f"added no field")

    # CONTROL RE-PROVED: the index is still writable and still searchable after the rejection.
    status, after = _signed(ctx, host, "PUT", f"/{_INDEX}/_doc/after",
                            body={"title": "after", "views": 9})
    assert status == 201, (
        f"a conforming document written after the rejection returned HTTP {status!r}, expected "
        f"201 -- the parse failure must not wedge the index: {after!r}")
    status, refreshed = _signed(ctx, host, "POST", f"/{_INDEX}/_refresh")
    assert status == 200, f"the second _refresh returned HTTP {status!r}: {refreshed!r}"
    status, result = _signed(ctx, host, "POST", f"/{_INDEX}/_search",
                             body={"size": 10, "track_total_hits": True,
                                   "query": {"match_all": {}}})
    assert status == 200, f"_search returned HTTP {status!r}, expected 200: {result!r}"
    assert _hit_ids(result) == ["after", "control"], (
        f"_search returned ids {_hit_ids(result)!r}, expected ['after', 'control'] -- exactly the "
        f"two documents that conformed to the mapping: hits={result.get('hits')!r}")
    assert _total(result) == 2, (
        f"_search reports {_total(result)!r} hits, expected 2: hits={result.get('hits')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
