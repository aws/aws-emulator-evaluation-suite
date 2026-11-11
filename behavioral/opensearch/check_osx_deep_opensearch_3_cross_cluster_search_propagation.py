"""osx-deep-opensearch-3-cross-cluster-search-propagation."""
from __future__ import annotations

import base64
import json
import random
import secrets
import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "osx-deep-opensearch-3-cross-cluster-search-propagation"
GROUP = "data-plane"
SERVICES = ["opensearch"]


ENGINE_VERSION = "OpenSearch_2.13"
# Cross-cluster search excludes T2/T3 instance types: a t3 peer is accepted by
# CreateOutboundConnection and then settles at VALIDATION_FAILED.
INSTANCE_TYPE = "m5.large.search"
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")
_SCENARIO = "osx-cross-cluster-search-propagation"

# Marks a domain endpoint the target published and then failed to answer on.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# Documents are distinguishable by domain: every document carries its domain's role, and the two
# domains hold DIFFERENT id sets and counts under the SAME index name, so a cross-cluster query
# that silently fell back to the local index cannot match the remote expectation by accident.
_LOCAL_IDS = ["local-a", "local-b"]
_REMOTE_IDS = ["remote-a", "remote-b", "remote-c"]


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _basic_request(ctx, method, url, user, password, *, body=None):
    """HTTP-basic-authenticated request to a fine-grained-access-control domain endpoint."""
    data = json.dumps(body).encode() if body is not None else None
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": f"Basic {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    # Trust exactly what ctx.http_verify names: False -> unverified, a path -> that CA bundle.
    verify = ctx.http_verify
    ssl_ctx = _ssl_context(verify)
    try:
        with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer at all
        raise AssertionError(
            f"{DATAPLANE_MARKER}: basic-auth {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return f"<no error object in {payload!r}>"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _throttled(fn, **kwargs):
    """fn(**kwargs), retried with exponential backoff (2-30 s, 8 attempts) while throttled."""
    for attempt in range(8):
        try:
            return fn(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES or attempt == 7:
                raise
        time.sleep(min(30.0, 2.0 * 2**attempt))
    raise AssertionError("unreachable")


def _domain_status(osc, domain_name: str, deadline: float) -> dict:
    """DescribeDomain's DomainStatus, retried every 2 s on throttling until ``deadline``."""
    while True:
        try:
            return osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            if (exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2.0)


def _delete_domain_bounded(osc, domain_name: str, timeout_s: float = 240.0) -> None:
    """Idempotent, bounded domain teardown.

    A domain whose connection is still being torn down can refuse deletion for a short while, so
    this retries for a bounded window and then re-raises rather than leave a cluster running.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osc.delete_domain(DomainName=domain_name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_outbound_quietly(osc, connection_id: str) -> None:
    try:
        osc.delete_outbound_connection(ConnectionId=connection_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_ccs_domain(ctx, master_user: str, master_password: str) -> str:
    """Create a domain eligible to be a cross-cluster peer; cleanup registered BEFORE the create.

    Cross-cluster search needs a non-T instance type, node-to-node encryption and fine-grained
    access control (whose co-requisites are encryption at rest and EnforceHTTPS).
    """
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain_name = ctx.unique_name("sim2real-osx-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_bounded(osc, domain_name))
    domain_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}"
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={"InstanceType": INSTANCE_TYPE, "InstanceCount": 1,
                       "DedicatedMasterEnabled": False, "ZoneAwarenessEnabled": False},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        EncryptionAtRestOptions={"Enabled": True},
        NodeToNodeEncryptionOptions={"Enabled": True},
        DomainEndpointOptions={"EnforceHTTPS": True,
                               "TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07"},
        AdvancedSecurityOptions={
            "Enabled": True,
            "InternalUserDatabaseEnabled": True,
            # The SAME internal admin user on both peers: cross-cluster search forwards the
            # caller's identity, and the remote domain authorizes it against its own role mapping.
            # Generated per run, never logged.
            "MasterUserOptions": {"MasterUserName": master_user,
                                  "MasterUserPassword": master_password},
        },
        # With FGAC on, the security plugin is the authorizer, so the resource policy admits any
        # caller on the index path from the runner's own addresses and no one else. The second
        # statement is the documented grant a DESTINATION domain needs before another domain may
        # run cross-cluster requests against it; it carries no data path of its own.
        AccessPolicies=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "es:*",
                 "Resource": f"{domain_arn}/*",
                 "Condition": {"IpAddress": {"aws:SourceIp": ctx.ingress_cidrs()}}},
                {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "es:ESCrossClusterGet",
                 "Resource": domain_arn},
            ]}),
        TagList=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    for attempt in range(12):
        if attempt:
            time.sleep(6.0 * attempt + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1800.0) -> str:
    """Poll to Processing=False AND a published Endpoint; bounded, raising."""
    osc = ctx.client("opensearch")
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last: dict = {}
    while True:
        last = _domain_status(osc, domain_name, deadline)
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} searchable endpoint: the run budget ended first; not graded")
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})")


def _wait_master_auth(ctx, base: str, user: str, password: str, timeout_s: float = 600.0) -> None:
    """Processing=False does not mean the security plugin has loaded; poll an authorized call."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status, body = None, {}
    while True:
        status, body = _basic_request(ctx, "GET", f"{base}/_cluster/health", user, password)
        if status == 200:
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"master user's basic-auth call to {base}: the run budget ended first; not graded")
    raise _never_ready(
        f"master user's basic-auth call to {base} did not succeed within {timeout_s}s "
        f"(last HTTP {status!r}: {body!r})")


def _find_connection(osc, direction: str, connection_id: str):
    describe = (osc.describe_outbound_connections if direction == "outbound"
                else osc.describe_inbound_connections)
    token = None
    while True:
        kw = {"Filters": [{"Name": "connection-id", "Values": [connection_id]}]}
        if token:
            kw["NextToken"] = token
        resp = _throttled(describe, **kw)
        for c in resp.get("Connections", []):
            if c.get("ConnectionId") == connection_id:
                return c
        token = resp.get("NextToken")
        if not token:
            return None


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, what: str, ctx=None):
    timeout_s = _budget_s(ctx, timeout_s) if ctx is not None else timeout_s
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise _never_ready(f"{what} not reached within {timeout_s}s; last={last!r}")


def _search(ctx, base, path, user, password):
    return _basic_request(ctx, "POST", f"{base}/{path}/_search", user, password,
                          body={"query": {"match_all": {}}, "size": 50})


def _hits(result):
    return result.get("hits", {}).get("hits", []) if isinstance(result, dict) else []


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A cross-cluster connection makes the remote domain's documents searchable from the local
    endpoint under `<alias>:<index>`, an unknown alias is refused exactly, and deleting the
    connection revokes the identical query while both domains keep their data."""
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    master_user = "sim2real-master"
    master_password = f"Sim2Real!{secrets.token_urlsafe(18)}Aa1"

    local_name = _create_ccs_domain(ctx, master_user, master_password)
    remote_name = _create_ccs_domain(ctx, master_user, master_password)

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_local = pool.submit(_wait_searchable, ctx, local_name)
        f_remote = pool.submit(_wait_searchable, ctx, remote_name)
        local_base = ctx.endpoint_url(f_local.result())
        remote_base = ctx.endpoint_url(f_remote.result())
    _wait_master_auth(ctx, local_base, master_user, master_password)
    _wait_master_auth(ctx, remote_base, master_user, master_password)

    # --- distinguishable documents, same index name on both domains ---
    index = ctx.unique_name("sim2real-ccs-")
    for base, role, domain, ids in ((local_base, "local", local_name, _LOCAL_IDS),
                                    (remote_base, "remote", remote_name, _REMOTE_IDS)):
        for doc_id in ids:
            status, body = _basic_request(
                ctx, "PUT", f"{base}/{index}/_doc/{doc_id}?refresh=true", master_user, master_password,
                body={"origin": role, "domain": domain, "doc": doc_id})
            assert status == 201, f"indexing {doc_id!r} into {domain} returned HTTP {status}: {body!r}"

    status, local_only = _search(ctx, local_base, index, master_user, master_password)
    assert status == 200, f"local _search returned HTTP {status}: {local_only!r}"
    local_seen = sorted(h["_id"] for h in _hits(local_only))
    assert local_seen == sorted(_LOCAL_IDS), (
        f"the local index should hold exactly the local documents; got {local_seen!r}")

    # --- connect local -> remote, accept on the inbound side, poll both sides to ACTIVE ---
    alias = ctx.unique_name("sim2realccs")
    created = osc.create_outbound_connection(
        ConnectionAlias=alias,
        ConnectionMode="DIRECT",
        LocalDomainInfo={"AWSDomainInformation": {
            "OwnerId": account_id, "DomainName": local_name, "Region": ctx.region}},
        RemoteDomainInfo={"AWSDomainInformation": {
            "OwnerId": account_id, "DomainName": remote_name, "Region": ctx.region}},
    )
    conn_id = created["ConnectionId"]
    ctx.on_cleanup(lambda: _delete_outbound_quietly(osc, conn_id))
    assert created["ConnectionAlias"] == alias, (
        f"CreateOutboundConnection echoed alias {created.get('ConnectionAlias')!r}, sent {alias!r}")

    _poll(lambda: _find_connection(osc, "inbound", conn_id),
          lambda c: c is not None and c["ConnectionStatus"]["StatusCode"] == "PENDING_ACCEPTANCE",
          timeout_s=600.0, interval_s=2.0, what="inbound connection PENDING_ACCEPTANCE", ctx=ctx)
    osc.accept_inbound_connection(ConnectionId=conn_id)
    _poll(lambda: _find_connection(osc, "outbound", conn_id),
          lambda c: c is not None and c["ConnectionStatus"]["StatusCode"] == "ACTIVE",
          timeout_s=900.0, interval_s=2.0, what="outbound connection ACTIVE", ctx=ctx)
    inbound = _poll(lambda: _find_connection(osc, "inbound", conn_id),
                    lambda c: c is not None and c["ConnectionStatus"]["StatusCode"] == "ACTIVE",
                    timeout_s=300.0, interval_s=2.0, what="inbound connection ACTIVE", ctx=ctx)
    assert inbound["RemoteDomainInfo"]["AWSDomainInformation"]["DomainName"] == remote_name, (
        f"inbound connection names remote {inbound['RemoteDomainInfo']!r}, expected {remote_name!r}")

    # --- the cross-cluster query, from the QUERYING (local) domain's endpoint ---
    ccs_path = f"{alias}:{index}"
    status, remote_result = _poll(
        lambda: _search(ctx, local_base, ccs_path, master_user, master_password),
        lambda r: r[0] == 200,
        timeout_s=300.0, interval_s=2.0,
        what=f"HTTP 200 from cross-cluster _search {ccs_path!r} on the local endpoint", ctx=ctx)
    hits = _hits(remote_result)
    remote_seen = sorted(h["_id"] for h in hits)
    assert remote_seen == sorted(_REMOTE_IDS), (
        f"cross-cluster search must return exactly the REMOTE domain's documents "
        f"{sorted(_REMOTE_IDS)!r}; got {remote_seen!r}")
    origins = sorted({h["_source"]["origin"] for h in hits})
    assert origins == ["remote"], f"cross-cluster hits carried origins {origins!r}, expected ['remote']"
    domains = sorted({h["_source"]["domain"] for h in hits})
    assert domains == [remote_name], f"cross-cluster hits came from {domains!r}, expected {remote_name!r}"
    indexes = sorted({h["_index"] for h in hits})
    assert indexes == [ccs_path], (
        f"cross-cluster hits must be attributed to {ccs_path!r}; _index values were {indexes!r}")

    # --- an unknown alias is refused exactly, with the real alias still serving (control) ---
    bogus_path = f"{ctx.unique_name('sim2realnope')}:{index}"
    bogus_status, bogus_body = _search(ctx, local_base, bogus_path, master_user, master_password)
    assert bogus_status == 404, (
        f"a cross-cluster query on an unknown alias must be refused with 404, got HTTP "
        f"{bogus_status}: {bogus_body!r}")
    assert _error_type(bogus_body) == "index_not_found_exception", (
        f"unknown-alias refusal type was {_error_type(bogus_body)!r}: {bogus_body!r}")
    status, again = _search(ctx, local_base, ccs_path, master_user, master_password)
    assert status == 200 and sorted(h["_id"] for h in _hits(again)) == sorted(_REMOTE_IDS), (
        f"positive control: the live alias must still serve the remote documents after the unknown-"
        f"alias refusal; got HTTP {status}: {again!r}")

    # --- delete the connection: the identical cross-cluster query must now fail ---
    osc.delete_outbound_connection(ConnectionId=conn_id)
    _poll(lambda: _find_connection(osc, "outbound", conn_id),
          lambda c: c is None or c["ConnectionStatus"]["StatusCode"] == "DELETED",
          timeout_s=600.0, interval_s=2.0, what="outbound connection DELETED", ctx=ctx)
    revoked_status, revoked_body = _poll(
        lambda: _search(ctx, local_base, ccs_path, master_user, master_password),
        lambda r: r[0] != 200,
        timeout_s=600.0, interval_s=2.0,
        what=f"cross-cluster _search {ccs_path!r} to stop succeeding after DeleteOutboundConnection",
        ctx=ctx)
    assert revoked_status == 404, (
        f"after DeleteOutboundConnection the same cross-cluster query must be refused with 404, got "
        f"HTTP {revoked_status}: {revoked_body!r}")
    assert _error_type(revoked_body) == "index_not_found_exception", (
        f"revoked-alias refusal type was {_error_type(revoked_body)!r}: {revoked_body!r}")

    # Positive controls: local data untouched, and the remote documents still exist on the remote
    # domain itself — the revocation removed the ROUTE, not the data.
    status, local_after = _search(ctx, local_base, index, master_user, master_password)
    assert status == 200 and sorted(h["_id"] for h in _hits(local_after)) == sorted(_LOCAL_IDS), (
        f"local index after revocation: HTTP {status}: {local_after!r}")
    status, remote_direct = _search(ctx, remote_base, index, master_user, master_password)
    assert status == 200 and sorted(h["_id"] for h in _hits(remote_direct)) == sorted(_REMOTE_IDS), (
        f"remote index read directly after revocation: HTTP {status}: {remote_direct!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
