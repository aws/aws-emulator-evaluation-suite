"""fgac-field-level-security-hides-field-from-hit-and-from-query."""
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

CHECK = "fgac-field-level-security-hides-field-from-hit-and-from-query"
GROUP = 'overly-permissive'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

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

# Prefix of the failure raised when a domain endpoint the target published does not answer, so
# that outcome reads as the target's failure rather than as a local network problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# The CONTROL-PLANE convergence counterpart, for a domain accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The verdict for a resource that never reached its ready state, the same on every target.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


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
    chunked decoding are all ours. A target may serve a well-formed JSON body through a helpful
    HTTP library and still not be an OpenSearch node, and owning the socket is what keeps the
    protocol itself graded. It also keeps the check free of a third-party client that is not
    installed everywhere this check runs.
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
    except OSError as exc:  # the endpoint the target published refused a TCP connect
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
    domain_name = ctx.unique_name("sim2real-osfls-")[:28].rstrip("-")
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
        # every filtering decision this check observes comes from the role rather than from IAM.
        AccessPolicies=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": "*"},
                           "Action": "es:*",
                           "Resource": f"arn:aws:es:{ctx.region}:{account_id}:"
                                       f"domain/{domain_name}/*"}]}),
        # Tagged at creation, in the same call, so tag-based cleanup can find the domain if this
        # check's own cleanup never runs.
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
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})")


def _wait_admin_auth(ctx, host: str, user: str, password: str, timeout_s: float = 420.0) -> None:
    """Processing=False does not mean the security plugin has loaded its config yet.

    Polls the admin user's own cluster-health call, which is the observable condition -- and it is
    the BARRIER for everything after it: the filtering this check grades is only meaningful once an
    authorized call is known to work.
    """
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _basic(ctx, host, "GET", "/_cluster/health", user, password)
        if status == 200:
            return
        time.sleep(2)
    raise _never_ready(
        f"the admin user's basic-auth call did not succeed within {timeout_s}s "
        f"(last HTTP {status!r}: {body!r})")


def _wait_role_effective(ctx, host: str, path: str, user: str, password: str,
                         timeout_s: float = 300.0) -> tuple:
    """Wait until a just-created role mapping has taken effect, on the POSITIVE path.

    Security-config changes propagate to the plugin's own index asynchronously and a
    not-yet-effective mapping answers 403 -- so the barrier is a SUCCESSFUL authorized search, never
    the absence under test. A field that is missing because the role is not loaded yet looks
    identical to a field the role removed, which is exactly the confusion this rules out.
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
    raise _never_ready(
        f"the restricted user's permitted search never succeeded within {timeout_s}s, so an absent "
        f"field could not be attributed to field-level security "
        f"(last HTTP {status!r}: {body!r})")


def _wait_grant_revoked(ctx, host: str, path: str, user: str, password: str,
                        timeout_s: float = 300.0) -> tuple:
    """Wait until a just-DELETED role mapping has stopped granting, polling the refusal.

    The same asynchrony as ``_wait_role_effective``, in the other direction: the security plugin's
    config propagates to the nodes after the API call returns, so asserting the refusal on the very
    next request grades propagation speed rather than the revocation. This polls for the observable
    condition -- a non-200 answer to a search the user could make a moment ago -- and returns
    whatever it last saw so the caller pins the exact status.
    """
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while time.monotonic() < deadline:
        status, body = _basic(ctx, host, "POST", path, user, password,
                              body={"size": 10, "track_total_hits": True,
                                    "query": {"match_all": {}}})
        if status != 200:
            return status, body
        time.sleep(2)
    return status, body


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _sources(result) -> list:
    return [hit.get("_source", {}) for hit in result.get("hits", {}).get("hits", [])]


# ===== end shared domain helpers =====


_SCENARIO = "fgac-field-level-security-hides-field"
_INDEX = "sim2real-osfls-personnel"
_ROLE = "sim2real_osfls_no_salary_role"
_LIMITED_USER = "sim2realosflslimited"
# The mapping is explicit so the excluded field is a `keyword`: a term query and a terms
# aggregation both have to be legal on it for the admin user, or "the restricted user sees
# nothing" would be a mapping artefact rather than a security decision.
_MAPPING = {"properties": {"title": {"type": "keyword"},
                           "department": {"type": "keyword"},
                           "salary": {"type": "keyword"}}}
_DOC = {"title": "principal-engineer", "department": "platform", "salary": "190000"}
# `~field` is the security plugin's EXCLUSION form for field-level security. The role grants read
# on the index and removes exactly one field, so the field is the only thing that differs between
# the two identities.
_EXCLUDED = "salary"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:native",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Field-level security drops one field from a mapped internal user's `_search` hit and `GET _doc`
    source and makes a term query and terms aggregation over it find nothing, while the admin user
    still sees the field on the same document.
    """
    admin_user = "sim2realosflsadmin"
    # Generated at run time and never logged: no assert message below interpolates a password.
    admin_password = "Aa1!" + secrets.token_urlsafe(18)
    limited_password = "Bb2!" + secrets.token_urlsafe(18)

    domain = _create_fgac_domain(ctx, admin_user, admin_password, scenario=_SCENARIO)
    host = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_admin_auth(ctx, host, admin_user, admin_password)

    status, created = _basic(ctx, host, "PUT", f"/{_INDEX}", admin_user, admin_password,
                             body={"settings": {"index": {"number_of_shards": 1,
                                                          "number_of_replicas": 0}},
                                   "mappings": _MAPPING})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _basic(ctx, host, "DELETE", f"/{_INDEX}", admin_user, admin_password))
    status, indexed = _basic(ctx, host, "PUT", f"/{_INDEX}/_doc/1", admin_user, admin_password,
                             body=dict(_DOC))
    assert status == 201, f"indexing into {_INDEX!r} returned HTTP {status!r}: {indexed!r}"
    status, refreshed = _basic(ctx, host, "POST", f"/{_INDEX}/_refresh", admin_user, admin_password)
    assert status == 200, f"_refresh of {_INDEX!r} returned HTTP {status!r}: {refreshed!r}"

    # EFFECT PRESENT, before anything is restricted: the field is stored and it is queryable.
    status, baseline = _basic(ctx, host, "POST", f"/{_INDEX}/_search", admin_user, admin_password,
                              body={"size": 10, "track_total_hits": True,
                                    "query": {"term": {_EXCLUDED: _DOC[_EXCLUDED]}}})
    assert status == 200, f"the admin user's baseline search returned HTTP {status!r}: {baseline!r}"
    assert _total(baseline) == 1, (
        f"the admin user's term query on {_EXCLUDED!r} found {_total(baseline)!r} documents before "
        f"any role existed, expected 1: hits={baseline.get('hits')!r}")
    assert _sources(baseline)[0].get(_EXCLUDED) == _DOC[_EXCLUDED], (
        f"the stored document reports {_EXCLUDED}={_sources(baseline)[0].get(_EXCLUDED)!r}, "
        f"expected {_DOC[_EXCLUDED]!r} -- the absence asserted below is only meaningful if the "
        f"field was there to begin with")

    status, role_body = _basic(
        ctx, host, "PUT", f"/_plugins/_security/api/roles/{_ROLE}", admin_user, admin_password,
        body={"cluster_permissions": ["cluster_composite_ops_ro"],
              "index_permissions": [{"index_patterns": [_INDEX],
                                     "fls": [f"~{_EXCLUDED}"],
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

    # POSITIVE CONTROL and propagation barrier: the restricted user reads the document it is
    # allowed to read, so everything asserted after this is about the FIELD, not about access.
    ok_status, ok_body = _wait_role_effective(
        ctx, host, f"/{_INDEX}/_search", _LIMITED_USER, limited_password)
    assert ok_status == 200, (
        f"the positive control failed: the restricted user got HTTP {ok_status!r} on the index its "
        f"role grants read on: {ok_body!r}")
    assert _total(ok_body) == 1, (
        f"the restricted user's search returned {_total(ok_body)!r} hits, expected 1 -- field-level "
        f"security removes a field, never the document: hits={ok_body.get('hits')!r}")
    restricted_source = _sources(ok_body)[0]
    assert restricted_source.get("title") == _DOC["title"], (
        f"the restricted user read title={restricted_source.get('title')!r}, expected "
        f"{_DOC['title']!r} -- the unrestricted fields must still be served")
    assert restricted_source.get("department") == _DOC["department"], (
        f"the restricted user read department={restricted_source.get('department')!r}, expected "
        f"{_DOC['department']!r}")

    # THE ONE THING THAT DIFFERS: the excluded field is absent from the restricted user's hit.
    assert _EXCLUDED not in restricted_source, (
        f"field-level security did not remove {_EXCLUDED!r}: the restricted user's hit source is "
        f"{restricted_source!r}")
    # EFFECT ABSENT, stated over the whole response rather than one key, so a copy of the value
    # relayed anywhere else in the envelope is caught too.
    assert _DOC[_EXCLUDED] not in json.dumps(ok_body), (
        f"the excluded field's value {_DOC[_EXCLUDED]!r} still appears somewhere in the restricted "
        f"user's search response: {ok_body!r}")

    # The exclusion is not a response-shaping trick: the field is unqueryable for that identity.
    status, denied_term = _basic(ctx, host, "POST", f"/{_INDEX}/_search", _LIMITED_USER,
                                 limited_password,
                                 body={"size": 10, "track_total_hits": True,
                                       "query": {"term": {_EXCLUDED: _DOC[_EXCLUDED]}}})
    assert status == 200, (
        f"the restricted user's term query on the excluded field returned HTTP {status!r}, expected "
        f"200 -- field-level security hides the field, it does not refuse the search: "
        f"{denied_term!r}")
    assert _total(denied_term) == 0, (
        f"the restricted user's term query on {_EXCLUDED!r} matched {_total(denied_term)!r} "
        f"documents, expected 0 -- a hidden field that can still be matched leaks its value one "
        f"query at a time: hits={denied_term.get('hits')!r}")
    status, denied_agg = _basic(ctx, host, "POST", f"/{_INDEX}/_search", _LIMITED_USER, limited_password,
                                body={"size": 0,
                                      "aggs": {"by_excluded": {"terms": {"field": _EXCLUDED}}}})
    assert status == 200, (
        f"the restricted user's terms aggregation over the excluded field returned HTTP {status!r}, "
        f"expected 200: {denied_agg!r}")
    buckets = denied_agg.get("aggregations", {}).get("by_excluded", {}).get("buckets")
    assert buckets == [], (
        f"the restricted user's terms aggregation over {_EXCLUDED!r} returned buckets {buckets!r}, "
        f"expected [] -- an aggregation is a read of the field by another name")

    # Absent on the realtime path too, so the filtering is not confined to the search route.
    status, got = _basic(ctx, host, "GET", f"/{_INDEX}/_doc/1", _LIMITED_USER, limited_password)
    assert status == 200, (
        f"the restricted user's GET by id returned HTTP {status!r}, expected 200: {got!r}")
    assert got.get("found") is True, (
        f"the restricted user's GET by id reports found={got.get('found')!r}, expected True -- "
        f"field-level security must not hide the document: {got!r}")
    assert _EXCLUDED not in got.get("_source", {}), (
        f"the excluded field survives the realtime GET path: {got.get('_source')!r}")

    # THE DIFFERENTIAL: the admin user reads the same document on the same index and still sees the
    # field, so every absence above is authorisation rather than the field having been deleted.
    status, admin_got = _basic(ctx, host, "GET", f"/{_INDEX}/_doc/1", admin_user, admin_password)
    assert status == 200, (
        f"the admin user's GET by id returned HTTP {status!r}, expected 200: {admin_got!r}")
    assert admin_got.get("_source", {}).get(_EXCLUDED) == _DOC[_EXCLUDED], (
        f"the admin user reads {_EXCLUDED}="
        f"{admin_got.get('_source', {}).get(_EXCLUDED)!r}, expected {_DOC[_EXCLUDED]!r} -- the "
        f"absences above can only be attributed to field-level security if the field is still "
        f"there for a privileged identity")
    status, admin_term = _basic(ctx, host, "POST", f"/{_INDEX}/_search", admin_user, admin_password,
                                 body={"size": 10, "track_total_hits": True,
                                       "query": {"term": {_EXCLUDED: _DOC[_EXCLUDED]}}})
    assert status == 200, (
        f"the admin user's term query returned HTTP {status!r}, expected 200: {admin_term!r}")
    assert _total(admin_term) == 1, (
        f"the admin user's term query on {_EXCLUDED!r} matched {_total(admin_term)!r} documents "
        f"after the role was created, expected 1 -- the role must restrict ONLY the user it is "
        f"mapped to: hits={admin_term.get('hits')!r}")

    # CONTROL RE-PROVED after the differential: removing the role mapping restores the field to the
    # same user, so the filtering was the mapping's doing and nothing else's.
    status, unmapped = _basic(ctx, host, "DELETE", f"/_plugins/_security/api/rolesmapping/{_ROLE}",
                              admin_user, admin_password)
    assert status == 200, (
        f"deleting the role mapping returned HTTP {status!r}, expected 200: {unmapped!r}")
    status, after = _wait_grant_revoked(ctx, host, f"/{_INDEX}/_search", _LIMITED_USER,
                                        limited_password)
    assert status == 403, (
        f"the unmapped user got HTTP {status!r} on the index, expected 403 -- an internal user with "
        f"no role mapping has no grant at all: {after!r}")
    assert _DOC[_EXCLUDED] not in json.dumps(after), (
        f"the refusal served to the unmapped user leaks the restricted field's value: {after!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
