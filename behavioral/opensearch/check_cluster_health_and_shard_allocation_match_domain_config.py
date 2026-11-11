"""cluster-health-and-shard-allocation-match-domain-config."""
from __future__ import annotations

import http.client
import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "cluster-health-and-shard-allocation-match-domain-config"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology: one t3.small.search data node, no dedicated cluster manager
# nodes, no zone awareness, minimum gp3 volume; teardown is registered before create.
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
# The CONTROL-PLANE convergence counterpart, for a domain that was accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """The "resource did not converge" verdict, the same on every target.

    A state the target ACCEPTED and then never reached within the budget carries STATE_MARKER, so
    it reads as the target's answer rather than as a local environment problem. The wait that
    raises it polls the same terminal condition with the same budget on every target.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted.

    Deliberately NOT silent about anything else. ``ctx.on_cleanup`` swallows exceptions, so a
    delete that fails for any other reason leaks a 24x7 cluster while the check still passes --
    raising here is what puts the failure in the run log where an operator can see it.
    """
    try:
        osc.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


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
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    # Registered BEFORE the create so a failure between create and registration can never leak a
    # 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        # Tagged at creation so tag-based cleanup can find leaked domains: it discovers what to
        # delete through the Resource Groups Tagging API and sees nothing else.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * (1 + attempt) + random.uniform(0, 6.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep.

    The budget is sized so the whole check fits an 1800 s per-check timeout; provisioning this
    topology takes roughly 11-14 min.
    """
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
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for THIS account (not boto3's ambient chain):
    signing as the wrong principal makes the domain's account-scoped policy 403 the request.
    Sends with stdlib urllib so no third-party HTTP client is needed.
    """
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()
    if raw is not None:
        data = raw if isinstance(raw, bytes) else raw.encode()
    elif body is not None:
        data = json.dumps(body).encode()
    else:
        data = None
    headers = {"Content-Type": content_type} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            text = resp.read().decode()
            return resp.status, (json.loads(text) if text else {})
    except urllib.error.HTTPError as exc:
        text = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(text)
        except ValueError:
            return exc.code, {"raw": text}
    except (OSError, http.client.HTTPException) as exc:  # the endpoint did not answer at all
        # An HTTP status (above) is data the caller asserts on; a transport failure is not, and
        # urllib reports it in wording that reads as a local network problem ("Connection refused",
        # "timed out"), which leaves the pass+fail denominator. The endpoint here was published by
        # the target itself, so failing to answer on it is the target's fidelity failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has the
    access policy yet; signed requests can 403 for a while. Poll a cheap GET until it clears.
    """
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    raise _never_ready(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}.

    Structural, single-valued and never an alternation: the engine puts the wrapper type in
    ``error.type`` and the underlying one in ``error.root_cause[0].type``, so a caller that wants
    the root cause asks for it by name rather than accepting either.
    """
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _root_cause_type(payload) -> str:
    """The FIRST root-cause type, for the exceptions the engine wraps one level deep."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        causes = error.get("root_cause") or []
        if causes and isinstance(causes[0], dict):
            return str(causes[0].get("type") or "")
    return ""


def _bulk_load(ctx, base: str, index: str, docs) -> None:
    """_bulk-index (id, source) pairs and assert the engine reported no per-item error."""
    lines = []
    for doc_id, source in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(source))
    status, body = _signed_request(ctx, "POST", f"{base}/_bulk", raw="\n".join(lines) + "\n",
                                   content_type="application/x-ndjson")
    assert status == 200, f"_bulk returned HTTP {status!r}: {body!r}"
    assert body.get("errors") is False, (
        f"_bulk reported per-item errors loading {index!r}: "
        f"{[i for i in body.get('items', []) if 'error' in i.get('index', {})]!r}"
    )


def _wait_index_status(ctx, base: str, index: str, want: str, timeout_s: float = 180.0) -> dict:
    """Poll _cluster/health for one index until it reaches a status; never a bare sleep.

    Bounded by the engine's own ``wait_for_status`` timeout inside a bounded outer loop, so a
    target that answers but never allocates fails rather than hangs.
    """
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        status, last = _signed_request(
            ctx, "GET", f"{base}/_cluster/health/{index}?wait_for_status={want}&timeout=30s")
        if status == 200 and last.get("timed_out") is False:
            return last
        time.sleep(2.0)
    raise _never_ready(
        f"index {index!r} did not reach status {want!r} within {timeout_s}s (last health {last!r})",
    )


def _hit_ids(result) -> list:
    return [h["_id"] for h in result.get("hits", {}).get("hits", [])]


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end shared domain helpers =====

_SCENARIO = "cluster-health-shard-allocation"


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A two-data-node zone-aware domain reports exactly two data nodes on the data plane, and a one-primary
    one-replica index reaches green with its two active shards on two different nodes, so InstanceCount governs
    data-plane shard placement.
    """
    domain = _create_min_domain(
        ctx, scenario=_SCENARIO,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 2,
                       "DedicatedMasterEnabled": False,
                       "ZoneAwarenessEnabled": True,
                       "ZoneAwarenessConfig": {"AvailabilityZoneCount": 2}})
    osc = ctx.client("opensearch")
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    declared = osc.describe_domain(DomainName=domain)["DomainStatus"]["ClusterConfig"]
    assert declared.get("InstanceCount") == 2, (
        f"the control plane reports InstanceCount {declared.get('InstanceCount')!r} for a domain "
        f"created with 2, so the data-plane comparison below has nothing to join to: {declared!r}"
    )
    assert declared.get("ZoneAwarenessEnabled") is True, (
        f"the control plane reports ZoneAwarenessEnabled "
        f"{declared.get('ZoneAwarenessEnabled')!r}, expected True: {declared!r}"
    )

    index = "sim2real-behav-alloc"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 1}},
        "mappings": {"properties": {"n": {"type": "integer"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    _bulk_load(ctx, base, index, [(f"alloc-{i}", {"n": i}) for i in range(4)])
    status, _ = _signed_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"_refresh returned HTTP {status!r}"

    health = _wait_index_status(ctx, base, index, "green", timeout_s=300.0)
    assert health.get("status") == "green", (
        f"cluster status is {health.get('status')!r} for a 1-primary 1-replica index on two "
        f"nodes, expected green: {health!r}"
    )
    assert health.get("number_of_data_nodes") == 2, (
        f"_cluster/health reports {health.get('number_of_data_nodes')!r} data nodes for an "
        f"InstanceCount of 2: {health!r}"
    )
    assert health.get("active_shards") == 2, (
        f"active_shards is {health.get('active_shards')!r}, expected 2 (one primary plus one "
        f"replica): {health!r}"
    )
    assert health.get("unassigned_shards") == 0, (
        f"unassigned_shards is {health.get('unassigned_shards')!r}, expected 0 -- an unassigned "
        f"replica means the second node cannot take it: {health!r}"
    )

    status, shards = _signed_request(ctx, "GET", f"{base}/_cat/shards/{index}?format=json")
    assert status == 200, f"_cat/shards returned HTTP {status!r}: {shards!r}"
    rows = [r for r in shards if r.get("index") == index]
    assert sorted(r.get("prirep") for r in rows) == ["p", "r"], (
        f"_cat/shards shows roles {sorted(r.get('prirep') for r in rows)!r} for {index!r}, "
        f"expected exactly one primary and one replica: {rows!r}"
    )
    assert {r.get("state") for r in rows} == {"STARTED"}, (
        f"_cat/shards reports states {sorted({r.get('state') for r in rows})!r}, expected both "
        f"copies STARTED: {rows!r}"
    )
    placed_on = [r.get("node") for r in rows]
    assert len(set(placed_on)) == 2, (
        f"the primary and its replica are both on node {placed_on!r}; a replica must not be "
        f"allocated onto its primary's node or it protects against nothing: {rows!r}"
    )

    status, nodes = _signed_request(ctx, "GET", f"{base}/_cat/nodes?format=json")
    assert status == 200, f"_cat/nodes returned HTTP {status!r}: {nodes!r}"
    assert len(nodes) == 2, (
        f"_cat/nodes lists {len(nodes)!r} nodes, expected 2 for an InstanceCount of 2 with no "
        f"dedicated cluster manager nodes: {nodes!r}"
    )
    assert set(placed_on) <= {n.get("name") for n in nodes}, (
        f"_cat/shards places copies on {sorted(set(placed_on))!r}, which is not a subset of the "
        f"nodes _cat/nodes lists ({sorted(n.get('name') for n in nodes)!r})"
    )

    status, body = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"deleting index {index!r} returned HTTP {status!r}: {body!r}"
    status, body = _signed_request(ctx, "GET", f"{base}/{index}")
    assert status == 404, (
        f"index {index!r} still answers HTTP {status!r} after DeleteIndex, expected 404: {body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
