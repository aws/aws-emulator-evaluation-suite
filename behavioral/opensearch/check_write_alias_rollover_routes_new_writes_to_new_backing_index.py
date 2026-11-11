"""write-alias-rollover-routes-new-writes-to-new-backing-index."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "write-alias-rollover-routes-new-writes-to-new-backing-index"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared data-plane helpers (also used by

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a real
# cost-leak class, so this provisions the cheapest legal cluster (one t3.small.search data node, no
# dedicated cluster manager nodes, no zone awareness, minimum gp3 volume) and registers teardown BEFORE create.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Marks a failure of the domain endpoint the target itself published, so it reads as the
# target's own fault rather than a connection problem on the caller's side.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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
        # Tagged at creation so a tag-based cleanup can find an orphaned domain.
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
    # The jitter is inside the bounded 12-attempt loop, never a bare pre-loop sleep, so a target
    # that answers immediately still incurs it exactly once and the wait stays capped.
    for attempt in range(12):
        if attempt == 0:
            time.sleep(random.uniform(0, 20.0))
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
    osc = ctx.client("opensearch")
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            # DescribeDomain is rate limited per account; a throttled poll is retried.
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


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wires for this run (not boto3's ambient chain): signing as
    the wrong principal makes the domain's account-scoped policy 403 the request. Sends with
    stdlib urllib so no third-party HTTP client is needed.
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
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        # An HTTP status (above) is data the caller asserts on; a transport failure is not. The
        # endpoint here was published by the target itself, so failing to answer on it is the
        # target's failure.
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
    raise AssertionError(
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
    raise AssertionError(
        f"index {index!r} did not reach status {want!r} within {timeout_s}s (last health {last!r})",
    )


def _hit_ids(result) -> list:
    return [h["_id"] for h in result.get("hits", {}).get("hits", [])]


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


# ===== end shared data-plane helpers =====

_SCENARIO = "write-alias-rollover"

# The conditions map the engine renders, MEASURED on OpenSearch 2.11.0. Rendered as a bracketed
# key rather than the bare condition name, which is why it is pinned rather than guessed.
_EXPECTED_CONDITIONS = {"[max_docs: 2]": True}


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Writes through an is_write_index alias land in the current backing index; after a
    `_rollover` on max_docs the write target moves to the new index, so writes before and after
    land in different indices while a search through the alias still returns every document once.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    alias = "sim2real-behav-roll"
    first, second = f"{alias}-000001", f"{alias}-000002"
    status, created = _signed_request(ctx, "PUT", f"{base}/{first}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"n": {"type": "integer"}}}})
    assert status == 200, f"creating {first!r} returned HTTP {status!r}: {created!r}"
    status, aliased = _signed_request(ctx, "POST", f"{base}/_aliases", body={"actions": [
        {"add": {"index": first, "alias": alias, "is_write_index": True}}]})
    assert status == 200, f"adding the write alias returned HTTP {status!r}: {aliased!r}"
    assert aliased.get("acknowledged") is True, f"_aliases was not acknowledged: {aliased!r}"

    early_ids = [f"early-{i}" for i in range(3)]
    for n, doc_id in enumerate(early_ids):
        # Written through the ALIAS, never through an index name: the routing is the subject.
        status, body = _signed_request(ctx, "PUT", f"{base}/{alias}/_doc/{doc_id}", body={"n": n})
        assert status == 201, f"writing {doc_id!r} through the alias returned HTTP {status!r}: {body!r}"
        assert body.get("_index") == first, (
            f"the alias routed {doc_id!r} to {body.get('_index')!r}, expected the only backing "
            f"index {first!r}"
        )
    status, _ = _signed_request(ctx, "POST", f"{base}/{alias}/_refresh")
    assert status == 200, f"_refresh before the rollover returned HTTP {status!r}"

    status, rollover = _signed_request(ctx, "POST", f"{base}/{alias}/_rollover",
                                       body={"conditions": {"max_docs": 2}})
    assert status == 200, f"_rollover returned HTTP {status!r}: {rollover!r}"
    assert rollover.get("rolled_over") is True, (
        f"_rollover reported rolled_over={rollover.get('rolled_over')!r} with 3 documents against "
        f"max_docs 2: {rollover!r}"
    )
    assert rollover.get("old_index") == first, (
        f"_rollover named {rollover.get('old_index')!r} as the old index, expected {first!r}"
    )
    assert rollover.get("new_index") == second, (
        f"_rollover created {rollover.get('new_index')!r}, expected the suffix-incremented "
        f"{second!r} -- the naming convention is what makes a rollover chain navigable"
    )
    conditions = rollover.get("conditions")
    assert conditions == _EXPECTED_CONDITIONS, (
        f"_rollover reported conditions {conditions!r}, expected {_EXPECTED_CONDITIONS!r} -- "
        f"exactly the max_docs condition, met"
    )

    late_ids = [f"late-{i}" for i in range(2)]
    for n, doc_id in enumerate(late_ids):
        status, body = _signed_request(ctx, "PUT", f"{base}/{alias}/_doc/{doc_id}",
                                       body={"n": 10 + n})
        assert status == 201, f"writing {doc_id!r} after the rollover returned HTTP {status!r}: {body!r}"
        assert body.get("_index") == second, (
            f"after the rollover the alias routed {doc_id!r} to {body.get('_index')!r}, expected "
            f"the new backing index {second!r}"
        )
    status, _ = _signed_request(ctx, "POST", f"{base}/{alias}/_refresh")
    assert status == 200, f"_refresh after the rollover returned HTTP {status!r}"

    counts = {}
    for index in (first, second):
        status, body = _signed_request(ctx, "GET", f"{base}/{index}/_count")
        assert status == 200, f"_count on {index!r} returned HTTP {status!r}: {body!r}"
        counts[index] = body.get("count")
    assert (counts[first], counts[second]) == (3, 2), (
        f"the backing indices hold {(counts[first], counts[second])!r} documents, expected (3, 2) "
        f"-- a rollover must neither move nor duplicate what is already written"
    )

    status, searched = _signed_request(ctx, "POST", f"{base}/{alias}/_search",
                                       body={"size": 20, "query": {"match_all": {}}})
    assert status == 200, f"searching the alias returned HTTP {status!r}: {searched!r}"
    assert sorted(_hit_ids(searched)) == sorted(early_ids + late_ids), (
        f"searching the alias returned {sorted(_hit_ids(searched))!r}, expected all five ids "
        f"exactly once: {sorted(early_ids + late_ids)!r}"
    )

    status, aliases = _signed_request(ctx, "GET", f"{base}/{alias}/_alias")
    assert status == 200, f"reading the alias back returned HTTP {status!r}: {aliases!r}"
    write_targets = sorted(
        index for index, entry in aliases.items()
        if entry.get("aliases", {}).get(alias, {}).get("is_write_index") is True)
    assert write_targets == [second], (
        f"is_write_index is true on {write_targets!r}, expected only the new backing index "
        f"[{second!r}] -- two write targets for one alias is an ambiguous routing table: "
        f"{aliases!r}"
    )

    for index in (first, second):
        status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
        assert status == 200, f"deleting {index!r} returned HTTP {status!r}: {deleted!r}"
        assert deleted.get("acknowledged") is True, (
            f"deleting {index!r} was not acknowledged: {deleted!r}"
        )
    for index in (first, second):
        status, body = _signed_request(ctx, "GET", f"{base}/{index}/_count")
        assert status == 404, (
            f"counting the deleted index {index!r} returned HTTP {status!r}, expected 404: {body!r}"
        )
        assert _error_type(body) == "index_not_found_exception", (
            f"counting the deleted index {index!r} returned error type {_error_type(body)!r}, "
            f"expected 'index_not_found_exception': {body!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
