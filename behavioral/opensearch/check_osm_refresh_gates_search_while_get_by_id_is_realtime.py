"""osm-refresh-gates-search-while-get-by-id-is-realtime."""
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

CHECK = "osm-refresh-gates-search-while-get-by-id-is-realtime"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== self-contained HTTP/TLS plumbing =====

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

# A data-plane failure the target itself produced: the domain endpoint it published did not
# answer. Distinct wording from a connection/environment error so it scores as a fidelity failure
# rather than being mistaken for one.
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
    chunked decoding are all ours, so a target that serves a well-formed JSON body through a
    generic HTTP library but is not an OpenSearch node still fails here.
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
        # A transport failure is not data a caller can assert on. The host here was published by
        # the target itself, so failing to answer on it is the target's failure.
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

    Signs with the credentials ctx wires for the target account, never boto3's ambient chain:
    signing as the wrong principal makes the domain's account-scoped policy 403 the request, which
    reads exactly like a fidelity failure. Only `Authorization` and `X-Amz-Date` are signed
    headers; `Host` is signed by value and sent verbatim by `_native_request`.
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


# ===== end self-contained HTTP/TLS plumbing =====

_SCENARIO = "osm-refresh-visibility"
_INDEX = "sim2real-osm-refresh"
# >= 3x the 1 s DEFAULT automatic refresh interval, so a target that merely refreshes on the
# default cadence cannot pass the invisibility legs by being slow.
_FREEZE_WINDOW_S = 4.0


def _search_all(ctx, host: str) -> dict:
    status, result = _signed(ctx, host, "POST", f"/{_INDEX}/_search",
                             body={"size": 10, "track_total_hits": True,
                                   "query": {"match_all": {}}})
    assert status == 200, f"_search returned HTTP {status!r}, expected 200: {result!r}"
    return result


def _count(ctx, host: str) -> int:
    status, result = _signed(ctx, host, "GET", f"/{_INDEX}/_count")
    assert status == 200, f"_count returned HTTP {status!r}, expected 200: {result!r}"
    return result["count"]


@tags("axis:happy-path", "concern:data-plane", "dp:native", "plane:data", "cap:c1")
def run(ctx) -> None:
    """With automatic refresh disabled, a written document is realtime-readable by id and invisible to
    `_search`/`_count` until an explicit `_refresh`, and a second document written after that refresh is hidden
    again while the first stays visible.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    host = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, host)

    status, created = _signed(ctx, host, "PUT", f"/{_INDEX}", body={
        "settings": {"index": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            # The whole subject of the check: automatic refresh OFF.
            "refresh_interval": "-1",
        }},
        "mappings": {"properties": {"marker": {"type": "keyword"}}}})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed(ctx, host, "DELETE", f"/{_INDEX}"))
    assert created.get("acknowledged") is True, (
        f"index creation reported acknowledged={created.get('acknowledged')!r}, expected True: "
        f"{created!r}")

    # The control is DEMONSTRATED, not assumed: the cluster must report the interval it accepted,
    # or the invisibility below would prove nothing.
    status, settings = _signed(ctx, host, "GET", f"/{_INDEX}/_settings?flat_settings=true")
    assert status == 200, f"reading {_INDEX!r} settings returned HTTP {status!r}: {settings!r}"
    interval = settings[_INDEX]["settings"].get("index.refresh_interval")
    assert interval == "-1", (
        f"index {_INDEX!r} reports index.refresh_interval {interval!r}, expected '-1': "
        f"{settings!r}")

    # A document written with the DEFAULT refresh policy.
    status, indexed = _signed(ctx, host, "PUT", f"/{_INDEX}/_doc/withheld?refresh=false",
                              body={"marker": "withheld"})
    assert status == 201, (
        f"indexing the withheld document returned HTTP {status!r}, expected 201: {indexed!r}")
    assert indexed.get("result") == "created", (
        f"indexing the withheld document reported result {indexed.get('result')!r}, expected "
        f"'created': {indexed!r}")

    # POSITIVE CONTROL, same wiring, same instant: the realtime GET-by-id must find it.
    status, fetched = _signed(ctx, host, "GET", f"/{_INDEX}/_doc/withheld")
    assert status == 200, (
        f"realtime GET of the withheld document returned HTTP {status!r}, expected 200 -- the "
        f"document must be IN the cluster for the invisibility legs to mean anything: {fetched!r}")
    assert fetched.get("found") is True, (
        f"realtime GET reports found={fetched.get('found')!r}, expected True: {fetched!r}")
    assert fetched["_source"]["marker"] == "withheld", (
        f"realtime GET returned _source {fetched.get('_source')!r}, expected marker 'withheld'")

    # FREEZE DETECTOR: every read across a window >= 3x the documented default cadence must return
    # the SAME zero answer, on two independent observables. The window always spans at least three
    # read pairs, however slow each read is.
    started = time.monotonic()
    reads = 0
    while time.monotonic() - started < _FREEZE_WINDOW_S or reads < 3:
        result = _search_all(ctx, host)
        hidden = _total(result)
        assert hidden == 0, (
            f"_search reports {hidden!r} hits {time.monotonic() - started:.1f}s after a "
            f"?refresh=false write into an index with refresh_interval=-1, expected 0 -- the "
            f"document is realtime-readable by id, so a searchable document here means the target "
            f"ignores the refresh contract: hits={result.get('hits')!r}")
        hidden_count = _count(ctx, host)
        assert hidden_count == 0, (
            f"_count reports {hidden_count!r} while the document is unrefreshed, expected 0 -- a "
            f"second independent observable of the same invisibility")
        reads += 1
        time.sleep(0.5)

    # THE TRANSITION: an explicit refresh, and nothing else, makes it searchable.
    status, refreshed = _signed(ctx, host, "POST", f"/{_INDEX}/_refresh")
    assert status == 200, f"_refresh returned HTTP {status!r}, expected 200: {refreshed!r}"
    assert refreshed["_shards"]["failed"] == 0, (
        f"_refresh reports {refreshed['_shards']['failed']!r} failed shards, expected 0: "
        f"{refreshed!r}")
    assert refreshed["_shards"]["successful"] == 1, (
        f"_refresh reports {refreshed['_shards']['successful']!r} successful shards, expected 1 "
        f"for a 1-shard 0-replica index: {refreshed!r}")

    result = _search_all(ctx, host)
    assert _total(result) == 1, (
        f"after an explicit _refresh, _search reports {_total(result)!r} hits, expected 1: "
        f"hits={result.get('hits')!r}")
    assert _hit_ids(result) == ["withheld"], (
        f"_search returned ids {_hit_ids(result)!r}, expected ['withheld']")
    assert result["hits"]["hits"][0]["_source"]["marker"] == "withheld", (
        f"the revealed hit carries _source {result['hits']['hits'][0].get('_source')!r}, expected "
        f"marker 'withheld'")
    revealed_count = _count(ctx, host)
    assert revealed_count == 1, (
        f"_count reports {revealed_count!r} after the refresh, expected 1")

    # THE GATE RE-ARMS. A target that treats the first _refresh as "searchability on" passes
    # everything above and fails here.
    status, second = _signed(ctx, host, "PUT", f"/{_INDEX}/_doc/second?refresh=false",
                             body={"marker": "second"})
    assert status == 201, (
        f"indexing the second document returned HTTP {status!r}, expected 201: {second!r}")
    status, second_fetched = _signed(ctx, host, "GET", f"/{_INDEX}/_doc/second")
    assert status == 200 and second_fetched.get("found") is True, (
        f"realtime GET of the second document returned HTTP {status!r} found="
        f"{second_fetched.get('found')!r}, expected 200/True: {second_fetched!r}")

    started = time.monotonic()
    rearm_reads = 0
    while time.monotonic() - started < _FREEZE_WINDOW_S or rearm_reads < 3:
        result = _search_all(ctx, host)
        assert _hit_ids(result) == ["withheld"], (
            f"_search returned ids {_hit_ids(result)!r} "
            f"{time.monotonic() - started:.1f}s after a second ?refresh=false write, expected "
            f"['withheld'] -- the refresh gate must re-arm, and the second document is "
            f"realtime-readable by id: hits={result.get('hits')!r}")
        rearm_count = _count(ctx, host)
        assert rearm_count == 1, (
            f"_count reports {rearm_count!r} with one document unrefreshed, expected 1")
        rearm_reads += 1
        time.sleep(0.5)

    status, refreshed = _signed(ctx, host, "POST", f"/{_INDEX}/_refresh")
    assert status == 200, f"the second _refresh returned HTTP {status!r}: {refreshed!r}"
    result = _search_all(ctx, host)
    assert _hit_ids(result) == ["second", "withheld"], (
        f"after the second _refresh, _search returned ids {_hit_ids(result)!r}, expected "
        f"['second', 'withheld']: hits={result.get('hits')!r}")
    final_count = _count(ctx, host)
    assert final_count == 2, (
        f"_count reports {final_count!r} after the second refresh, expected 2")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
