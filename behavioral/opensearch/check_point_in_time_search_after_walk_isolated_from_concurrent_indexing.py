"""point-in-time-search-after-walk-isolated-from-concurrent-indexing."""
from __future__ import annotations

import http.client
import json
import random
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "point-in-time-search-after-walk-isolated-from-concurrent-indexing"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== domain lifecycle and signed-request helpers =====

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

# A domain endpoint the target published and then failed to answer on is this target's own
# fidelity failure, not a connection problem on our side; this marker in the assertion message is
# what keeps it graded that way.
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
    # CreateDomain is aggressively rate limited per account: jitter before the first attempt (to
    # avoid colliding with other concurrent runs), then back off on throttling. The wait is bounded
    # and lives inside the retry loop it serves, rather than as a bare pre-loop sleep.
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


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep.

    The budget is sized so the whole check fits an 1800 s runner timeout; provisioning this
    topology takes ~680-850 s.
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
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx wired for this account (not boto3's ambient chain): signing as
    the wrong principal makes the domain's account-scoped policy 403 the request.
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


# ===== end helpers =====

def _verified_domain_teardown(ctx, domain_name: str, timeout_s: float = 420.0) -> None:
    """Delete the domain INLINE and poll until the API confirms the deletion is committed.

    `on_cleanup` runs on a daemon thread joined with a 60 s cap and, by its own docstring, NEVER
    affects the verdict -- so a teardown that must be PROVEN cannot live only there. A domain that
    leaks bills per node-hour 24x7.

    The proof taken here is `DomainStatus.Deleted is True` (or an outright
    ResourceNotFoundException). Full disappearance from `describe_domain` takes a further ~10-15
    min of asynchronous teardown that no check can usefully sit through, but `Deleted: True` is the
    service stating the delete was accepted and is in progress, which is the strongest evidence
    available inside a check budget.
    """
    osc = ctx.client("opensearch")
    _delete_domain_quietly(osc, domain_name)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code not in _THROTTLE_CODES:
                raise
            time.sleep(2)
            continue
        if last.get("Deleted") is True:
            return
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name!r} never reported Deleted=True within {timeout_s}s of DeleteDomain "
        f"(last status Deleted={last.get('Deleted')!r} Processing={last.get('Processing')!r}) -- "
        f"a domain that will not tear down bills per node-hour")


_SCENARIO = "pit-search-after-under-load"
_INDEX = "sim2real-behav-pit"
_ORIGINALS = 500
_PAGE = 25
_PAGES = _ORIGINALS // _PAGE          # 20 full pages, then one empty page terminates the walk
_WRITERS = 20
_ROUNDS_PER_WRITER = 5
_NEW_PER_ROUND = 5
_TOTAL_ROUNDS = _WRITERS * _ROUNDS_PER_WRITER          # 100 rounds
_NEW_DOCS = _TOTAL_ROUNDS * _NEW_PER_ROUND             # 500 new documents
_DELETES = _TOTAL_ROUNDS                               # 100 deletions of seeded documents
_MID_PAGE = _PAGES // 2


def _orig_id(i: int) -> str:
    return f"orig-{i:04d}"


def _new_id(writer: int, round_: int, j: int) -> str:
    return f"new-{writer:02d}-{round_}{j}"


def _open_pit(ctx, base: str) -> str:
    status, body = _signed_request(
        ctx, "POST", f"{base}/{_INDEX}/_search/point_in_time?keep_alive=10m")
    assert status == 200, f"opening a point-in-time reader returned HTTP {status!r}: {body!r}"
    pit_id = body.get("pit_id")
    assert isinstance(pit_id, str) and pit_id, (
        f"the point-in-time response carried pit_id {pit_id!r}; the walk below needs a real "
        f"reader handle: {body!r}")
    return pit_id


def _close_pit(ctx, base: str, pit_id: str):
    return _signed_request(ctx, "DELETE", f"{base}/_search/point_in_time",
                           body={"pit_id": [pit_id]})


def _prefix_total(ctx, base: str, prefix: str, pit_id=None) -> int:
    """How many documents whose sort_id starts with ``prefix`` this view can see."""
    body = {"size": 0, "track_total_hits": True, "query": {"prefix": {"sort_id": prefix}}}
    path = "/_search"
    if pit_id is None:
        path = f"/{_INDEX}/_search"
    else:
        body["pit"] = {"id": pit_id, "keep_alive": "5m"}
    status, result = _signed_request(ctx, "POST", f"{base}{path}", body=body)
    assert status == 200, f"a {prefix!r} count returned HTTP {status!r}: {result!r}"
    return _total(result)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A point-in-time reader's `search_after` walk of 500 seeded documents returns exactly that
    set, with no duplicate or omission, while 500 concurrent writes land on and are visible on the
    live index -- proving a frozen snapshot rather than `from`/`size` pagination or no snapshot at all.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    # One shard, deliberately: a point-in-time reader is a per-shard segment view, and a single
    # shard makes "the frozen set is exactly these 500 ids" exact rather than merge-order dependent.
    status, created = _signed_request(ctx, "PUT", f"{base}/{_INDEX}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"sort_id": {"type": "keyword"}, "n": {"type": "integer"}}}})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"

    original_ids = {_orig_id(i) for i in range(_ORIGINALS)}
    _bulk_load(ctx, base, _INDEX,
               [(_orig_id(i), {"sort_id": _orig_id(i), "n": i}) for i in range(_ORIGINALS)])
    status, _ = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
    assert status == 200, f"the seed _refresh returned HTTP {status!r}"
    seeded = _prefix_total(ctx, base, "orig-")
    assert seeded == _ORIGINALS, (
        f"the index holds {seeded!r} seeded documents, expected {_ORIGINALS}")

    pit_id = _open_pit(ctx, base)
    ctx.on_cleanup(lambda: _close_pit(ctx, base, pit_id))

    # --- the 20 writers. Each owns a disjoint id range so no two can collide, and refreshes after
    # every round so its writes are genuinely VISIBLE to a live search while the walk is in flight.
    rounds_done = [0]
    write_failures = []
    progress_lock = threading.Lock()

    def _writer(w: int) -> str:
        for round_ in range(_ROUNDS_PER_WRITER):
            docs = [(_new_id(w, round_, j),
                     {"sort_id": _new_id(w, round_, j), "n": 10_000 + w * 100 + round_ * 10 + j})
                    for j in range(_NEW_PER_ROUND)]
            lines = []
            for doc_id, source in docs:
                lines.append(json.dumps({"index": {"_index": _INDEX, "_id": doc_id}}))
                lines.append(json.dumps(source))
            lines.append(json.dumps(
                {"delete": {"_index": _INDEX, "_id": _orig_id(w * _ROUNDS_PER_WRITER + round_)}}))
            # A 429 from a single-node t3.small.search is this runner pushing too hard, not a
            # fidelity signal, so it is retried INSIDE the writer with a bounded backoff.
            for attempt in range(6):
                status, body = _signed_request(
                    ctx, "POST", f"{base}/_bulk", raw="\n".join(lines) + "\n",
                    content_type="application/x-ndjson")
                if status == 200 and body.get("errors") is False:
                    break
                if status != 429:
                    with progress_lock:
                        write_failures.append((status, body))
                    return "failed"
                time.sleep(1.0 + attempt)
            else:
                with progress_lock:
                    write_failures.append(("throttled out", None))
                return "failed"
            _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
            with progress_lock:
                rounds_done[0] += 1
        return "ok"

    seen: list = []
    sort_values: list = []
    page_sizes: list = []
    echoed_pit_ids: list = []
    mid_live_new = None
    mid_pit_new = None
    cursor = None
    current_pit = pit_id

    pool = ThreadPoolExecutor(max_workers=_WRITERS)
    try:
        futures = [pool.submit(_writer, w) for w in range(_WRITERS)]
        for page_index in range(_PAGES + 1):
            # Barrier: do not fetch page N until the writers have committed their Nth slice, so
            # the walk provably INTERLEAVES with the mutations instead of outrunning them.
            want = min(_TOTAL_ROUNDS, (_TOTAL_ROUNDS // _PAGES) * (page_index + 1))
            barrier_deadline = time.monotonic() + 120.0
            while time.monotonic() < barrier_deadline:
                with progress_lock:
                    if rounds_done[0] >= want or write_failures:
                        break
                time.sleep(0.2)
            body = {"size": _PAGE, "pit": {"id": current_pit, "keep_alive": "5m"},
                    "sort": [{"sort_id": "asc"}], "track_total_hits": True}
            if cursor is not None:
                body["search_after"] = cursor
            status, page = _signed_request(ctx, "POST", f"{base}/_search", body=body)
            assert status == 200, (
                f"page {page_index} of the point-in-time walk returned HTTP {status!r}: {page!r}")
            echoed_pit_ids.append(page.get("pit_id"))
            hits = page.get("hits", {}).get("hits", [])
            page_sizes.append(len(hits))
            if page_index == _MID_PAGE:
                mid_live_new = _prefix_total(ctx, base, "new-")
                mid_pit_new = _prefix_total(ctx, base, "new-", pit_id=current_pit)
            if not hits:
                break
            current_pit = page.get("pit_id") or current_pit
            for hit in hits:
                seen.append(hit["_id"])
                sort_values.append(hit["sort"])
            cursor = hits[-1]["sort"]
        outcomes = [f.result() for f in futures]
    finally:
        pool.shutdown(wait=True)

    # --- the writers really wrote. Without this the isolation assertions below are vacuous.
    assert write_failures == [], (
        f"{len(write_failures)} concurrent _bulk batches failed, so the isolation assertions "
        f"would be about writes that never happened: {write_failures[:2]!r}")
    assert outcomes == ["ok"] * _WRITERS, (
        f"the {_WRITERS} writers reported {outcomes!r}, expected every one to complete")
    assert rounds_done[0] == _TOTAL_ROUNDS, (
        f"{rounds_done[0]} of {_TOTAL_ROUNDS} write rounds committed")

    # --- the concurrency proof: mid-walk, a live view had already moved on and the reader had not.
    assert mid_live_new is not None and mid_live_new > 0, (
        f"at page {_MID_PAGE} a LIVE search saw {mid_live_new!r} of the concurrently indexed "
        f"new-* documents; if none had landed yet the walk merely outran the writers and every "
        f"isolation assertion below would be vacuous")
    assert mid_pit_new == 0, (
        f"at page {_MID_PAGE} the point-in-time reader saw {mid_pit_new!r} new-* documents while "
        f"a live search saw {mid_live_new!r} of them -- the frozen view must contain none")

    # --- the walk itself.
    assert page_sizes == [_PAGE] * _PAGES + [0], (
        f"the walk returned page sizes {page_sizes!r}, expected {_PAGES} full pages of {_PAGE} "
        f"and then one empty page to terminate it")
    assert len(seen) == _ORIGINALS, (
        f"the walk yielded {len(seen)} hits in total, expected exactly {_ORIGINALS}")
    assert len(set(seen)) == _ORIGINALS, (
        f"the walk yielded {len(seen)} hits but only {len(set(seen))} distinct ids, so at least "
        f"one document was returned twice: "
        f"{sorted({i for i in seen if seen.count(i) > 1})[:5]!r}")
    assert set(seen) == original_ids, (
        f"the walk enumerated a different set than the {_ORIGINALS} documents that existed when "
        f"the reader was opened: {len(set(seen) - original_ids)} unexpected "
        f"({sorted(set(seen) - original_ids)[:5]!r}) and "
        f"{len(original_ids - set(seen))} missing ({sorted(original_ids - set(seen))[:5]!r})")
    leaked = sorted(i for i in seen if i.startswith("new-"))
    assert leaked == [], (
        f"{len(leaked)} concurrently indexed documents leaked into the frozen walk "
        f"({leaked[:5]!r}); {_NEW_DOCS} were indexed and refreshed while it was in flight and the "
        f"reader must see none of them")
    deleted_ids = {_orig_id(w * _ROUNDS_PER_WRITER + r)
                   for w in range(_WRITERS) for r in range(_ROUNDS_PER_WRITER)}
    assert len(deleted_ids) == _DELETES, (
        f"the deletion plan covers {len(deleted_ids)} ids, expected {_DELETES}")
    assert deleted_ids <= set(seen), (
        f"{len(deleted_ids - set(seen))} of the {_DELETES} documents deleted DURING the walk "
        f"vanished from it ({sorted(deleted_ids - set(seen))[:5]!r}) -- a frozen reader must "
        f"outlive a deletion")
    assert all(sort_values[i] < sort_values[i + 1] for i in range(len(sort_values) - 1)), (
        f"the concatenated sort values are not strictly ascending across the walk, so the cursor "
        f"is not a sort tuple: first descent at "
        f"{next((sort_values[i:i + 2] for i in range(len(sort_values) - 1) if sort_values[i] >= sort_values[i + 1]), None)!r}")
    assert all(isinstance(p, str) and p for p in echoed_pit_ids), (
        f"not every page echoed a pit_id back: {[p for p in echoed_pit_ids if not p]!r}")

    # --- the control that dates the whole thing: the mutations really landed on the live index.
    status, _ = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
    assert status == 200, f"the post-walk _refresh returned HTTP {status!r}"
    status, live = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_search",
                                  body={"size": 0, "track_total_hits": True,
                                        "query": {"match_all": {}}})
    assert status == 200, f"the post-walk live search returned HTTP {status!r}: {live!r}"
    expected_live = _ORIGINALS + _NEW_DOCS - _DELETES
    assert _total(live) == expected_live, (
        f"after the writers finished a live search reports {_total(live)!r} documents, expected "
        f"{expected_live} ({_ORIGINALS} + {_NEW_DOCS} - {_DELETES}) -- this is what proves the "
        f"frozen walk was isolated from real mutations rather than from failed ones")
    live_new = _prefix_total(ctx, base, "new-")
    assert live_new == _NEW_DOCS, (
        f"a live search sees {live_new!r} new-* documents, expected all {_NEW_DOCS}")

    # --- the same cursor mechanism against a LIVE view does see the writes: isolates the frozen
    # behaviour to the reader rather than to search_after.
    # "m" sits between nothing and "new-", and `new-` sorts before `orig-`, so the first live page
    # after it is entirely the concurrently indexed documents -- the ones the frozen walk refused
    # to show. Same cursor mechanism, same sort, different view.
    status, live_after = _signed_request(
        ctx, "POST", f"{base}/{_INDEX}/_search",
        body={"size": _PAGE, "sort": [{"sort_id": "asc"}], "search_after": ["m"]})
    assert status == 200, f"a live search_after returned HTTP {status!r}: {live_after!r}"
    live_ids = _hit_ids(live_after)
    assert len(live_ids) == _PAGE and all(i.startswith("new-") for i in live_ids), (
        f"a LIVE search_after from the same cursor position returned {live_ids!r}; it must see the "
        f"concurrently indexed new-* documents, which is what confines the isolation above to the "
        f"point-in-time reader rather than to search_after itself")

    status, closed = _close_pit(ctx, base, pit_id)
    assert status == 200, f"closing the point-in-time reader returned HTTP {status!r}: {closed!r}"
    assert closed.get("pits", [{}])[0].get("successful") is True, (
        f"closing the reader reported {closed!r}, expected successful=true")

    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{_INDEX}")
    assert status == 200, f"deleting index {_INDEX!r} returned HTTP {status!r}: {deleted!r}"
    status, gone = _signed_request(ctx, "GET", f"{base}/{_INDEX}")
    assert status == 404, (
        f"a GET on the deleted index {_INDEX!r} answered HTTP {status!r}, expected 404: {gone!r}")

    _verified_domain_teardown(ctx, domain)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
