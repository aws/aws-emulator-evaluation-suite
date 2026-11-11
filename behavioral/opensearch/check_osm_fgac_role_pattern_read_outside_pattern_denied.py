"""osm-fgac-role-pattern-read-outside-pattern-denied."""
from __future__ import annotations

import base64
import json
import random
import secrets
import socket
import ssl
import urllib.parse
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "osm-fgac-role-pattern-read-outside-pattern-denied"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']

# ===== self-contained helpers =====

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

# A data-plane FAIL marker: a check detail containing this string is scored as the target's own
# failure rather than an environment or connectivity gap, so a domain endpoint the target
# published and then failed to answer on is graded as a target failure.
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
    chunked decoding are all ours. That is deliberate rather than ornamental: a target may serve
    a well-formed JSON body through a helpful HTTP library and still not be an OpenSearch node, so
    owning the socket is what actually grades the protocol. It also keeps the check free of a
    third-party client that is not installed everywhere this runs.
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


def _basic(ctx, host, method, path, user, password, *, body=None):
    """HTTP-basic-authenticated OpenSearch request over a TLS socket we open ourselves.

    Fine-grained access control authenticates the internal user database over basic auth, NOT
    SigV4 -- which is the whole point here: the identity under test is an OpenSearch user, not an
    IAM principal, so no AWS signer is involved on this path at all.
    """
    data = json.dumps(body).encode() if body is not None else None
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    return _native_request(ctx, host, method, path, headers=headers, body=data)


def _create_fgac_domain(ctx, admin_user: str, admin_password: str, *, scenario: str) -> str:
    """Create the cheapest legal FGAC domain, cleanup registered BEFORE the create call.

    Fine-grained access control has three co-requirements -- encryption at rest, node-to-node
    encryption and EnforceHTTPS -- and CreateDomain refuses the request without all three.
    """
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain_name = ctx.unique_name("sim2real-osm-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never leak a
    # 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        EncryptionAtRestOptions={"Enabled": True},
        NodeToNodeEncryptionOptions={"Enabled": True},
        DomainEndpointOptions={"EnforceHTTPS": True,
                               "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
        AdvancedSecurityOptions={
            "Enabled": True,
            "InternalUserDatabaseEnabled": True,
            "MasterUserOptions": {"MasterUserName": admin_user,
                                  "MasterUserPassword": admin_password},
        },
        # With FGAC on, the security plugin is the authorizer, so the resource policy is open and
        # every refusal this check observes comes from the role mapping rather than from IAM. This
        # is the configuration AWS documents for the internal user database; unauthenticated
        # requests are still refused, by FGAC.
        AccessPolicies=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": "*"},
                           "Action": "es:*",
                           "Resource": f"arn:aws:es:{ctx.region}:{account_id}:"
                                       f"domain/{domain_name}/*"}]}),
        # Tagged at creation so a tag-based cleanup can find the domain if teardown is
        # interrupted.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
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


def _wait_admin_auth(ctx, host: str, user: str, password: str, timeout_s: float = 420.0) -> None:
    """Processing=False does not mean the security plugin has loaded its config yet.

    Polls the admin user's own cluster-health call, which is the observable condition -- and it is
    the BARRIER for everything after it: the refusal this check grades is only meaningful once an
    authorized call is known to work, or a still-initialising plugin's 403 is indistinguishable
    from a real denial.
    """
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _basic(ctx, host, "GET", "/_cluster/health", user, password)
        if status == 200:
            return
        time.sleep(2)
    raise AssertionError(
        f"the admin user's basic-auth call did not succeed within {timeout_s}s "
        f"(last HTTP {status!r}: {body!r})")


def _wait_mapping_effective(ctx, host: str, path: str, user: str, password: str,
                            timeout_s: float = 300.0) -> tuple:
    """Wait until a just-created role mapping has taken effect, on the POSITIVE path.

    Security-config changes propagate to the plugin's own index asynchronously and a
    not-yet-effective mapping answers 403 -- the SAME status as the denial under test. So the
    barrier is a SUCCESSFUL authorized call, never the refusal itself: poll until the mapped user
    can read the index its role DOES name, and only then probe the one it must not read.
    """
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _basic(ctx, host, "POST", path, user, password,
                              body={"size": 10, "track_total_hits": True,
                                    "query": {"match_all": {}}})
        if status == 200:
            return status, body
        time.sleep(2)
    raise AssertionError(
        f"the mapped user's permitted index never became readable within {timeout_s}s, so a 403 "
        f"on the index outside the pattern could not be attributed to authorisation "
        f"(last HTTP {status!r}: {body!r})")


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


# ===== end self-contained helpers =====


_SCENARIO = "osm-fgac-index-pattern-denial"
# The role's pattern is a PREFIX wildcard, so the permitted index matches it and the other one does
# not. Both live only inside the domain this check creates, so neither name is account state.
_PATTERN = "sim2real-osm-allowed*"
_ALLOWED = "sim2real-osm-allowed-reports"
_OUTSIDE = "sim2real-osm-other-reports"
_CATALOGUE = "/_cat/indices/sim2real-osm-*?format=json"
_ROLE = "sim2real_osm_pattern_role"
_LIMITED_USER = "sim2realosmlimited"


def _catalogue_names(ctx, host: str, user: str, password: str) -> list:
    """Index names from `_cat/indices`, narrowed server-side to this check's own prefix.

    Narrowed on purpose: an unfiltered catalogue read also returns the security plugin's and
    Dashboards' own system indices, so asserting on the whole list would be asserting on cluster
    internals this check did not create.
    """
    status, rows = _basic(ctx, host, "GET", _CATALOGUE, user, password)
    assert status == 200, f"_cat/indices returned HTTP {status!r}, expected 200: {rows!r}"
    assert isinstance(rows, list), (
        f"_cat/indices?format=json returned {type(rows).__name__}, expected a JSON array: {rows!r}")
    return sorted(row["index"] for row in rows)


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An internal user mapped to a role whose index pattern names one index can search only that
    index, refused HTTP 403 `security_exception` on an index outside the pattern that the admin
    user can still read; deleting that index removes it from both `_search` and `_cat/indices`.
    """
    admin_user = "sim2realosmadmin"
    # Generated at run time and never logged: no assert message below interpolates a password.
    admin_password = "Aa1!" + secrets.token_urlsafe(18)
    limited_password = "Bb2!" + secrets.token_urlsafe(18)

    domain = _create_fgac_domain(ctx, admin_user, admin_password, scenario=_SCENARIO)
    host = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_admin_auth(ctx, host, admin_user, admin_password)

    for index, marker in ((_ALLOWED, "allowed-doc"), (_OUTSIDE, "outside-doc")):
        status, created = _basic(ctx, host, "PUT", f"/{index}", admin_user, admin_password,
                                 body={"settings": {"index": {"number_of_shards": 1,
                                                              "number_of_replicas": 0}}})
        assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
        ctx.on_cleanup(lambda i=index: _basic(ctx, host, "DELETE", f"/{i}", admin_user,
                                              admin_password))
        status, indexed = _basic(ctx, host, "PUT", f"/{index}/_doc/1", admin_user, admin_password,
                                 body={"marker": marker})
        assert status == 201, f"indexing into {index!r} returned HTTP {status!r}: {indexed!r}"
        status, refreshed = _basic(ctx, host, "POST", f"/{index}/_refresh", admin_user, admin_password)
        assert status == 200, f"_refresh of {index!r} returned HTTP {status!r}: {refreshed!r}"

    status, role_body = _basic(
        ctx, host, "PUT", f"/_plugins/_security/api/roles/{_ROLE}", admin_user, admin_password,
        body={"cluster_permissions": ["cluster_composite_ops_ro"],
              "index_permissions": [{"index_patterns": [_PATTERN],
                                     "allowed_actions": ["read", "search"]}]})
    ctx.on_cleanup(lambda: _basic(ctx, host, "DELETE", f"/_plugins/_security/api/roles/{_ROLE}",
                                  admin_user, admin_password))
    assert status == 201, f"creating role {_ROLE!r} returned HTTP {status!r}: {role_body!r}"

    status, user_body = _basic(
        ctx, host, "PUT", f"/_plugins/_security/api/internalusers/{_LIMITED_USER}",
        admin_user, admin_password, body={"password": limited_password})
    ctx.on_cleanup(lambda: _basic(
        ctx, host, "DELETE", f"/_plugins/_security/api/internalusers/{_LIMITED_USER}",
        admin_user, admin_password))
    assert status == 201, (
        f"creating internal user {_LIMITED_USER!r} returned HTTP {status!r}: {user_body!r}")

    status, map_body = _basic(
        ctx, host, "PUT", f"/_plugins/_security/api/rolesmapping/{_ROLE}",
        admin_user, admin_password, body={"users": [_LIMITED_USER]})
    ctx.on_cleanup(lambda: _basic(ctx, host, "DELETE",
                                  f"/_plugins/_security/api/rolesmapping/{_ROLE}",
                                  admin_user, admin_password))
    assert status == 201, (
        f"mapping {_LIMITED_USER!r} onto {_ROLE!r} returned HTTP {status!r}: {map_body!r}")

    # POSITIVE CONTROL and propagation barrier: the mapped user reads the index its pattern names.
    allowed_status, allowed_body = _wait_mapping_effective(
        ctx, host, f"/{_ALLOWED}/_search", _LIMITED_USER, limited_password)
    assert allowed_status == 200, (
        f"the positive control failed: the mapped user got HTTP {allowed_status!r} on the index "
        f"its role pattern names: {allowed_body!r}")
    assert _total(allowed_body) == 1, (
        f"the mapped user's search of the permitted index returned {_total(allowed_body)!r} hits, "
        f"expected 1: hits={allowed_body.get('hits')!r}")
    markers = [h.get("_source", {}).get("marker") for h in allowed_body["hits"]["hits"]]
    assert markers == ["allowed-doc"], (
        f"the mapped user read {markers!r} from the permitted index, expected ['allowed-doc']")

    # THE ONE THING THAT DIFFERS: an index the role's pattern does not match.
    denied_status, denied_body = _basic(ctx, host, "POST", f"/{_OUTSIDE}/_search", _LIMITED_USER,
                                        limited_password,
                                        body={"query": {"match_all": {}}})
    assert denied_status == 403, (
        f"the index outside the role pattern returned HTTP {denied_status!r} to the mapped user, "
        f"expected 403: {denied_body!r}")
    assert _error_type(denied_body) == "security_exception", (
        f"the refusal reports error.type {_error_type(denied_body)!r}, expected "
        f"'security_exception': {denied_body!r}")
    assert "indices:data/read/search" in str(denied_body), (
        f"the 403 body does not name the action that was refused: {denied_body!r} -- a refusal "
        f"that does not say what was missing is indistinguishable from an authentication failure")
    # EFFECT ABSENT: the refusal leaks none of the document it refused.
    assert "outside-doc" not in str(denied_body), (
        f"the refusal leaked the denied document's content: {denied_body!r}")
    # And the denial is index-level, not a quirk of the _search route.
    get_status, get_body = _basic(ctx, host, "GET", f"/{_OUTSIDE}/_doc/1", _LIMITED_USER,
                                  limited_password)
    assert get_status == 403, (
        f"a direct GET by id on the index outside the pattern returned HTTP {get_status!r} to the "
        f"mapped user, expected 403 -- a refusal that only covers _search is not an index-level "
        f"grant: {get_body!r}")
    assert _error_type(get_body) == "security_exception", (
        f"the GET refusal reports error.type {_error_type(get_body)!r}, expected "
        f"'security_exception': {get_body!r}")

    # The 403 is AUTHORISATION, not absence: the admin user reads the very same document.
    admin_status, admin_body = _basic(ctx, host, "POST", f"/{_OUTSIDE}/_search", admin_user,
                                        admin_password,
                                        body={"size": 10, "track_total_hits": True,
                                              "query": {"match_all": {}}})
    assert admin_status == 200, (
        f"the admin user got HTTP {admin_status!r} on the index outside the pattern, so the 403 "
        f"above cannot be attributed to authorisation: {admin_body!r}")
    admin_markers = [h.get("_source", {}).get("marker") for h in admin_body["hits"]["hits"]]
    assert admin_markers == ["outside-doc"], (
        f"the admin user reads {admin_markers!r} from that index, expected ['outside-doc'] -- "
        f"the refusal must be authorisation, not absence")

    # Both indices are in the catalogue before the delete, so the absence below is a change.
    before = _catalogue_names(ctx, host, admin_user, admin_password)
    assert before == sorted([_ALLOWED, _OUTSIDE]), (
        f"_cat/indices reports {before!r} for this check's prefix, expected "
        f"{sorted([_ALLOWED, _OUTSIDE])!r}")

    # DELETE, then gone from BOTH the query path and the catalogue.
    status, deleted = _basic(ctx, host, "DELETE", f"/{_OUTSIDE}", admin_user, admin_password)
    assert status == 200, f"deleting index {_OUTSIDE!r} returned HTTP {status!r}: {deleted!r}"
    assert deleted.get("acknowledged") is True, (
        f"index deletion reported acknowledged={deleted.get('acknowledged')!r}, expected True: "
        f"{deleted!r}")
    status, searched = _basic(ctx, host, "POST", f"/{_OUTSIDE}/_search", admin_user, admin_password,
                              body={"query": {"match_all": {}}})
    assert status == 404, (
        f"_search on the deleted index returned HTTP {status!r} to the admin user, expected 404: "
        f"{searched!r}")
    assert _error_type(searched) == "index_not_found_exception", (
        f"_search on the deleted index reports error.type {_error_type(searched)!r}, expected "
        f"'index_not_found_exception': {searched!r}")
    after = _catalogue_names(ctx, host, admin_user, admin_password)
    assert after == [_ALLOWED], (
        f"_cat/indices still reports {after!r} for this check's prefix, expected {[_ALLOWED]!r} -- "
        f"a deleted index that is gone from search but still listed is a catalogue that has "
        f"diverged from the data")

    # CONTROL RE-PROVED after the delete: the permitted index is still readable by the mapped user,
    # so the deletion removed exactly one index and the role mapping still holds.
    status, still = _basic(ctx, host, "POST", f"/{_ALLOWED}/_search", _LIMITED_USER, limited_password,
                           body={"size": 10, "track_total_hits": True,
                                 "query": {"match_all": {}}})
    assert status == 200, (
        f"the mapped user got HTTP {status!r} on its permitted index after the unrelated delete, "
        f"expected 200: {still!r}")
    assert _total(still) == 1, (
        f"the permitted index reports {_total(still)!r} hits after the unrelated delete, expected "
        f"1: hits={still.get('hits')!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
