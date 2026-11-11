"""osx-deep-opensearch-3-blue-green-scale-out-data-continuity."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "osx-deep-opensearch-3-blue-green-scale-out-data-continuity"
GROUP = "data-plane"
SERVICES = ["opensearch"]


ENGINE_VERSION = "OpenSearch_2.13"
INSTANCE_TYPE = "t3.small.search"
_THROTTLE_CODES = ("ThrottlingException", "Throttling", "TooManyRequestsException", "RequestLimitExceeded")
_SCENARIO = "osx-blue-green-scale-out"
N_DOCS = 24
# 3 primaries x 1 replica = 6 copies: enough that a balanced 3-node cluster must place a copy on
# every node, so "the new node holds a shard" is a property of allocation, not of luck.
N_SHARDS = 3

# Marks a domain endpoint the target published and then failed to answer on.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _signed_request(ctx, method: str, url: str, body=None, *, ndjson: bool = False):
    """Send a SigV4-signed ('es') HTTPS request to the domain endpoint; returns (status, json).

    Signs with ctx's credentials, never boto3's ambient chain, which the access policy would 403.
    """
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()

    if body is None:
        data, headers = None, {}
    elif ndjson:
        data = body.encode()
        headers = {"Content-Type": "application/x-ndjson"}
    else:
        data = json.dumps(body).encode()
        headers = {"Content-Type": "application/json"}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer at all
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


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


def _delete_domain_quietly(osc, domain_name: str) -> None:
    try:
        _throttled(osc.delete_domain, DomainName=domain_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _create_domain(ctx) -> str:
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    domain_name = ctx.unique_name("sim2real-osx-")[:28].rstrip("-")
    # Registered BEFORE the create so no failure path can leak a 24x7 cluster.
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={"InstanceType": INSTANCE_TYPE, "InstanceCount": 2,
                       "DedicatedMasterEnabled": False, "ZoneAwarenessEnabled": False},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow",
                           "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                           "Action": "es:*",
                           "Resource": f"arn:aws:es:{ctx.region}:{account_id}:"
                                       f"domain/{domain_name}/*"}]}),
        TagList=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    for attempt in range(12):
        if attempt:
            time.sleep(2.0 * attempt)
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_settled(ctx, domain_name: str, timeout_s: float) -> dict:
    """Poll to Processing=False AND a published Endpoint; bounded, raising."""
    osc = ctx.client("opensearch")
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = _throttled(osc.describe_domain, DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Endpoint"):
            return last
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to settle: the run budget ended first; not graded")
    raise _never_ready(
        f"domain {domain_name} did not settle within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})")


_IN_PROGRESS = (
    "A change/update is in progress. Please wait for it to complete before requesting another change."
)


def _update_when_accepted(ctx, osc, domain_name: str, **config) -> dict:
    """UpdateDomainConfig, polled past AWS's exact "change/update is in progress" refusal: post-create
    work keeps running behind Processing=False. Any other error raises."""
    budget = _budget_s(ctx, 300.0)
    deadline = time.monotonic() + budget
    while True:
        try:
            return _throttled(osc.update_domain_config, DomainName=domain_name, **config)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Message") != _IN_PROGRESS:
                raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"UpdateDomainConfig on {domain_name} to be accepted: the run budget ended first; not graded")
            raise AssertionError(
                f"UpdateDomainConfig on {domain_name} still refused as in progress after {budget}s")
        time.sleep(2.0)


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, what: str, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise _never_ready(f"{what} not reached within {timeout_s}s; last={last!r}")


def _doc_ids(ctx, base: str, index: str):
    """One continuity probe: (HTTP status, total hits, sorted ids) of a match_all _search."""
    status, body = _signed_request(ctx, "POST", f"{base}/{index}/_search",
                                   {"query": {"match_all": {}}, "size": N_DOCS * 2,
                                    "track_total_hits": True})
    if status != 200:
        return status, None, body
    total = body.get("hits", {}).get("total", {})
    total = total.get("value") if isinstance(total, dict) else total
    return status, total, sorted(h["_id"] for h in body["hits"]["hits"])


def _stage_snapshot(progress: dict):
    return tuple((s.get("Name"), s.get("Status"))
                 for s in progress.get("ChangeProgressStages") or [])


def _completed_stages(snapshot) -> int:
    return sum(1 for _name, status in snapshot if status == "COMPLETED")


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Scaling data nodes 2 -> 3: change-progress stages advance while in flight, every _search
    during the change returns the same N documents, and once COMPLETED the engine reports 3 nodes
    with shard copies on the joined node."""
    osc = ctx.client("opensearch")
    domain = _create_domain(ctx)
    status0 = _wait_settled(ctx, domain, timeout_s=1500.0)
    base = ctx.endpoint_url(status0["Endpoint"])

    # The data-plane authorizer can lag the control plane; poll a signed GET past the 403s.
    _poll(lambda: _signed_request(ctx, "GET", f"{base}/_cluster/health"),
          lambda r: r[0] == 200, timeout_s=_budget_s(ctx, 300.0), interval_s=2.0,
          what="HTTP 200 from signed _cluster/health", ctx=ctx)

    status, nodes_before = _signed_request(ctx, "GET", f"{base}/_cat/nodes?format=json")
    assert status == 200, f"_cat/nodes before scaling returned HTTP {status}: {nodes_before!r}"
    names_before = sorted(n["name"] for n in nodes_before)
    assert len(names_before) == 2, f"a 2-node domain reported nodes {nodes_before!r}"

    index = ctx.unique_name("sim2real-bg-")
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", {
        "settings": {"index": {"number_of_shards": N_SHARDS, "number_of_replicas": 1}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status}: {created!r}"
    expected_ids = sorted(f"doc-{i:03d}" for i in range(N_DOCS))
    bulk = "".join(
        json.dumps({"index": {"_index": index, "_id": doc_id}}) + "\n"
        + json.dumps({"doc": doc_id, "n": i}) + "\n"
        for i, doc_id in enumerate(expected_ids))
    status, bulk_resp = _signed_request(ctx, "POST", f"{base}/_bulk?refresh=true", bulk, ndjson=True)
    assert status == 200 and bulk_resp.get("errors") is False, (
        f"_bulk of {N_DOCS} documents returned HTTP {status}, errors={bulk_resp.get('errors')!r}")
    probe = _doc_ids(ctx, base, index)
    assert probe == (200, N_DOCS, expected_ids), f"pre-change _search returned {probe!r}"

    # --- the change, observed while in flight ---
    upd = _update_when_accepted(ctx, osc, domain,
                                ClusterConfig={"InstanceType": INSTANCE_TYPE, "InstanceCount": 3})
    change_id = upd["DomainConfig"]["ChangeProgressDetails"]["ChangeId"]
    assert change_id, f"UpdateDomainConfig returned no ChangeId: {upd['DomainConfig'].get('ChangeProgressDetails')!r}"

    deadline = time.monotonic() + _budget_s(ctx, 1500.0)
    in_flight_snapshots = []
    continuity_probes = 0
    final_progress = None
    while time.monotonic() < deadline:
        progress = _throttled(osc.describe_domain_change_progress,
                              DomainName=domain, ChangeId=change_id)["ChangeProgressStatus"]
        assert progress.get("ChangeId") == change_id, (
            f"change progress answered for {progress.get('ChangeId')!r}, asked for {change_id!r}")
        assert progress.get("Status") != "FAILED", f"the scale-out change FAILED: {progress!r}"
        if progress.get("Status") == "COMPLETED":
            final_progress = progress
            break
        snap = _stage_snapshot(progress)
        if snap:
            in_flight_snapshots.append(snap)
        # Data continuity WHILE the topology changes: the same N documents, HTTP 200, every probe.
        probe = _doc_ids(ctx, base, index)
        assert probe == (200, N_DOCS, expected_ids), (
            f"during the in-flight change (overall {progress.get('Status')!r}, stages {snap!r}) "
            f"_search returned {probe!r}; expected HTTP 200 with the same {N_DOCS} documents")
        continuity_probes += 1
        # The change runs for many minutes; a 4 s poll stays under DescribeDomainChangeProgress's rate limit.
        time.sleep(4.0)
    if final_progress is None:
        if _budget_spent(ctx):
            raise TimeoutError(f"change {change_id} to reach COMPLETED: the run budget ended first; not graded")
        raise _never_ready(f"change {change_id} did not reach COMPLETED within the budget; "
                           f"stages seen {in_flight_snapshots[-1:]!r}")

    final_snap = _stage_snapshot(final_progress)
    assert in_flight_snapshots, (
        f"no poll observed a non-empty ChangeProgressStages while the change was in flight "
        f"({continuity_probes} in-flight polls); final stages {final_snap!r}")
    assert continuity_probes >= 2, (
        f"only {continuity_probes} continuity probe(s) ran while the change was in flight")
    series = [_completed_stages(s) for s in in_flight_snapshots] + [_completed_stages(final_snap)]
    assert all(a <= b for a, b in zip(series, series[1:])), (
        f"COMPLETED-stage counts regressed between polls: {series!r}")
    assert series[-1] > series[0], (
        f"no stage advanced between polls: COMPLETED-stage counts {series!r}, first in-flight "
        f"{in_flight_snapshots[0]!r}, final {final_snap!r}")
    assert final_snap and all(st == "COMPLETED" for _n, st in final_snap), (
        f"a COMPLETED change must report every stage COMPLETED, got {final_snap!r}")

    # --- the topology the ENGINE reports, after the change ---
    settled = _wait_settled(ctx, domain, timeout_s=900.0)
    assert settled["ClusterConfig"]["InstanceCount"] == 3, (
        f"DescribeDomain InstanceCount after COMPLETED is {settled['ClusterConfig']['InstanceCount']!r}")

    nodes_after = _poll(
        lambda: _signed_request(ctx, "GET", f"{base}/_cat/nodes?format=json"),
        lambda r: r[0] == 200 and len(r[1]) == 3, timeout_s=_budget_s(ctx, 600.0), interval_s=2.0,
        what="_cat/nodes reporting exactly 3 nodes", ctx=ctx)[1]
    names_after = sorted(n["name"] for n in nodes_after)
    joined = sorted(set(names_after) - set(names_before))
    assert joined, f"no node joined: before {names_before!r}, after {names_after!r}"

    def _shard_layout():
        st, rows = _signed_request(ctx, "GET", f"{base}/_cat/shards/{index}?format=json")
        if st != 200:
            return st, rows, {}
        by_node: dict = {}
        for r in rows:
            if r.get("state") == "STARTED" and r.get("node"):
                by_node.setdefault(r["node"], []).append((r["shard"], r["prirep"]))
        return st, rows, by_node

    _st, shard_rows, by_node = _poll(
        _shard_layout,
        lambda r: r[0] == 200 and len(r[1]) == N_SHARDS * 2
        and all(x.get("state") == "STARTED" for x in r[1])
        and sorted(r[2]) == names_after,
        timeout_s=_budget_s(ctx, 600.0), interval_s=2.0,
        what=f"all {N_SHARDS * 2} shard copies STARTED across the 3 reported nodes", ctx=ctx)
    on_joined = {n: by_node[n] for n in joined if n in by_node}
    assert on_joined, (
        f"no shard copy was placed on a joined node {joined!r}; layout {by_node!r}")

    probe = _doc_ids(ctx, base, index)
    assert probe == (200, N_DOCS, expected_ids), f"post-change _search returned {probe!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
