"""bm25-relevance-ordering-and-explain-score-arithmetic."""
from __future__ import annotations

import http.client
import json
import math
import random
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

CHECK = "bm25-relevance-ordering-and-explain-score-arithmetic"
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
    # CreateDomain is aggressively rate limited per account: jitter on the first attempt, then
    # back off on throttling -- both live inside this bounded (12-attempt), raise-on-exhaustion
    # loop so neither sleep is unconditional.
    for attempt in range(12):
        time.sleep(random.uniform(0, 20.0) if attempt == 0 else 6.0 * attempt + random.uniform(0, 6.0))
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
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
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
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if last.get("Deleted") is True:
            return
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name!r} never reported Deleted=True within {timeout_s}s of DeleteDomain "
        f"(last status Deleted={last.get('Deleted')!r} Processing={last.get('Processing')!r}) -- "
        f"a domain that will not tear down bills per node-hour")


_SCENARIO = "bm25-relevance-ordering"
_INDEX = "sim2real-behav-bm25"
_COMMON_DOCS = 29          # identical documents: same tf, same df, same field length
_FLOOD_DOCS = 200          # the ranking-flip arm
_LONG_FILLER = 40


def _search(ctx, base: str, body: dict) -> dict:
    status, result = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_search", body=body)
    assert status == 200, f"_search returned HTTP {status!r} for {body!r}: {result!r}"
    return result


def _ranked(result) -> list:
    return [(h["_id"], h["_score"]) for h in result.get("hits", {}).get("hits", [])]


def _count(ctx, base: str, term: str) -> int:
    status, body = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_count",
                                   body={"query": {"match": {"body": term}}})
    assert status == 200, f"_count for {term!r} returned HTTP {status!r}: {body!r}"
    return body.get("count")


def _leaf(node, needle: str):
    """Depth-first search of an _explain tree for the node whose description STARTS WITH ``needle``.

    The tree shape is the engine's own account of HOW it scored, so the check reads the parameters
    (k1, b, dl, avgdl, n, N) out of it rather than hardcoding OpenSearch's defaults -- an engine
    that scores with different constants must still report the ones it used, and the arithmetic
    assertion below then has to close against those.

    A prefix match, not a substring one, and that is load-bearing: every parent describes its own
    formula, so `"boost"` appears inside `"score(freq=1.0), computed as boost * idf * tf from:"`
    and `"k1"` inside `"tf, computed as freq / (freq + k1 * ...)"`. A substring search therefore
    returns the PARENT's value for both and the arithmetic would close against itself.
    """
    if isinstance(node, dict):
        if str(node.get("description", "")).startswith(needle):
            return node
        for child in node.get("details") or []:
            found = _leaf(child, needle)
            if found is not None:
                return found
    return None


def _bm25_weight(term_node) -> tuple:
    """Recompute one term's BM25 weight from the leaves the engine reported.

    score = boost * idf * tf, with
      idf = log(1 + (N - n + 0.5) / (n + 0.5))
      tf  = freq / (freq + k1 * (1 - b + b * dl / avgdl))
    """
    boost = _leaf(term_node, "boost")
    idf = _leaf(term_node, "idf, computed as")
    tf = _leaf(term_node, "tf, computed as")
    assert boost is not None and idf is not None and tf is not None, (
        f"the _explain subtree does not expose boost/idf/tf leaves, so the engine did not report "
        f"a BM25 computation at all: {json.dumps(term_node)[:400]}")
    n = _leaf(idf, "n, number of documents containing term")
    big_n = _leaf(idf, "N, total number of documents with field")
    freq = _leaf(tf, "freq, occurrences of term within document")
    k1 = _leaf(tf, "k1, term saturation")
    b = _leaf(tf, "b, length normalization")
    dl = _leaf(tf, "dl, length of field")
    avgdl = _leaf(tf, "avgdl, average length")
    for name, node in (("n", n), ("N", big_n), ("freq", freq), ("k1", k1), ("b", b),
                       ("dl", dl), ("avgdl", avgdl)):
        assert node is not None, (
            f"the idf/tf subtree does not report {name!r}: "
            f"{json.dumps(term_node)[:400]}")
    computed_idf = math.log(1 + (big_n["value"] - n["value"] + 0.5) / (n["value"] + 0.5))
    assert abs(computed_idf - idf["value"]) < 1e-4, (
        f"the reported idf {idf['value']!r} does not follow from the n={n['value']!r} and "
        f"N={big_n['value']!r} it reported (recomputed {computed_idf!r})")
    computed_tf = freq["value"] / (
        freq["value"] + k1["value"] * (1 - b["value"] + b["value"] * dl["value"] / avgdl["value"]))
    assert abs(computed_tf - tf["value"]) < 1e-4, (
        f"the reported tf {tf['value']!r} does not follow from freq={freq['value']!r} "
        f"k1={k1['value']!r} b={b['value']!r} dl={dl['value']!r} avgdl={avgdl['value']!r} "
        f"(recomputed {computed_tf!r})")
    return boost["value"] * idf["value"] * tf["value"], int(n["value"])


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """BM25 decides result order: a rare term outranks a common one, a short field outranks a long one,
    `similarity: boolean` flattens scores to 1.0, `_explain` multiplies back to `_score`, and
    flooding the index with the rare term reverses the ranking.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    # One shard, mandatory: BM25 statistics are per-shard, so a multi-shard index makes the
    # exact-equality assertion below non-deterministic rather than wrong.
    # `bool_body` carries the identical text under `similarity: boolean`, so the ONLY variable
    # between the two ranking arms is the scoring function.
    status, created = _signed_request(ctx, "PUT", f"{base}/{_INDEX}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {
            "body": {"type": "text"},
            "bool_body": {"type": "text", "similarity": "boolean"},
            "sort_id": {"type": "keyword"}}}})
    assert status == 200, f"creating index {_INDEX!r} returned HTTP {status!r}: {created!r}"

    # A document set with hand-computed statistics: "common" in 30 documents, "zebra" in 1, and a
    # short/long pair each holding "pivot" exactly once so only field length varies.
    docs = []
    for i in range(_COMMON_DOCS):
        text = "common alpha bravo"
        docs.append((f"c{i:03d}", {"body": text, "bool_body": text, "sort_id": f"c{i:03d}"}))
    zebra_text = "zebra common alpha bravo"
    docs.append(("zebra", {"body": zebra_text, "bool_body": zebra_text, "sort_id": "z000"}))
    long_text = "pivot " + " ".join(f"w{i}" for i in range(_LONG_FILLER))
    docs.append(("pivot-short", {"body": "pivot", "bool_body": "pivot", "sort_id": "p000"}))
    docs.append(("pivot-long", {"body": long_text, "bool_body": long_text, "sort_id": "p001"}))
    _bulk_load(ctx, base, _INDEX, docs)
    status, _ = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
    assert status == 200, f"the seed _refresh returned HTTP {status!r}"

    # --- 1. a rare term dominates a common one.
    ranked = _ranked(_search(ctx, base, {"size": 5, "query": {"match": {"body": "zebra common"}}}))
    assert ranked and ranked[0][0] == "zebra", (
        f"'zebra common' ranked {ranked!r}; the document holding the df=1 term must come first, "
        f"because idf dominates a term held by {_COMMON_DOCS + 1} documents")
    assert ranked[0][1] > 2 * ranked[1][1], (
        f"the rare-term document scored {ranked[0][1]!r} against runner-up {ranked[1][1]!r}; a "
        f"df=1 term's idf must dominate a df={_COMMON_DOCS + 1} term's by more than 2x")

    # --- 2. identical statistics produce bit-identical scores.
    common_hits = _ranked(_search(ctx, base, {"size": 40, "query": {"match": {"body": "common"}}}))
    plain = [score for doc_id, score in common_hits if doc_id.startswith("c")]
    assert len(plain) == _COMMON_DOCS, (
        f"the 'common' search returned {len(plain)} of the {_COMMON_DOCS} identical documents")
    assert max(plain) - min(plain) < 1e-6, (
        f"{_COMMON_DOCS} documents with identical tf, df and field length scored across "
        f"[{min(plain)!r}, {max(plain)!r}]; a real BM25 gives them one value, and spread means a "
        f"heuristic scorer")

    # --- 3. field-length normalisation, with nothing else varying.
    pivot = _ranked(_search(ctx, base, {"size": 5, "query": {"match": {"body": "pivot"}}}))
    assert [doc_id for doc_id, _ in pivot] == ["pivot-short", "pivot-long"], (
        f"'pivot' ranked {pivot!r}; both documents hold the term exactly once, so the SHORTER "
        f"field must rank first -- that is the b parameter doing length normalisation")
    assert pivot[0][1] > pivot[1][1], (
        f"the short and long documents scored {pivot[0][1]!r} and {pivot[1][1]!r}")

    # --- 4. the same two documents on the boolean-similarity field: the setting really swapped the
    # scoring function rather than being accepted and ignored.
    bool_pivot = _ranked(_search(ctx, base, {"size": 5, "query": {"match": {"bool_body": "pivot"}}}))
    assert sorted(score for _, score in bool_pivot) == [1.0, 1.0], (
        f"on the similarity:boolean field the short/long pair scored {bool_pivot!r}, expected 1.0 "
        f"each -- the identical documents scored {pivot[0][1]!r} and {pivot[1][1]!r} under BM25, "
        f"so the only variable is the similarity setting")
    bool_common = _ranked(_search(ctx, base, {"size": 40,
                                              "query": {"match": {"bool_body": "common"}}}))
    assert {score for _, score in bool_common} == {1.0}, (
        f"on the similarity:boolean field the 'common' matches scored "
        f"{sorted({s for _, s in bool_common})!r}, expected every one at 1.0")

    # --- 5. _explain: the tree multiplies back to the score the search served.
    status, explained = _signed_request(
        ctx, "POST", f"{base}/{_INDEX}/_explain/zebra",
        body={"query": {"match": {"body": "zebra common"}}})
    assert status == 200, f"_explain returned HTTP {status!r}: {explained!r}"
    assert explained.get("matched") is True, (
        f"_explain on the top hit reports matched={explained.get('matched')!r}: {explained!r}")
    explanation = explained.get("explanation") or {}
    assert abs(explanation.get("value", 0.0) - ranked[0][1]) < 1e-5, (
        f"_explain reports value {explanation.get('value')!r} but the search served _score "
        f"{ranked[0][1]!r} for the same document and query")
    term_nodes = explanation.get("details") or []
    assert len(term_nodes) == 2, (
        f"the _explain tree has {len(term_nodes)} term contributions, expected one per query term "
        f"('zebra' and 'common'): {json.dumps(explanation)[:400]}")
    recomputed = 0.0
    doc_frequencies = {}
    for node in term_nodes:
        weight, doc_freq = _bm25_weight(node)
        recomputed += weight
        doc_frequencies[str(node.get("description", ""))] = doc_freq
    assert abs(recomputed - explanation["value"]) < 1e-4, (
        f"summing boost*idf*tf over the reported leaves gives {recomputed!r}, but the tree's own "
        f"total is {explanation['value']!r} -- the explanation does not account for the score")

    # --- 6. two independent surfaces agree on one statistic.
    zebra_df = next(v for k, v in doc_frequencies.items() if "zebra" in k)
    common_df = next(v for k, v in doc_frequencies.items() if "common" in k)
    assert zebra_df == _count(ctx, base, "zebra") == 1, (
        f"the idf leaf reports n={zebra_df!r} documents containing 'zebra' while _count reports "
        f"{_count(ctx, base, 'zebra')!r}; expected 1 from both")
    assert common_df == _count(ctx, base, "common") == _COMMON_DOCS + 1, (
        f"the idf leaf reports n={common_df!r} for 'common' while _count reports "
        f"{_count(ctx, base, 'common')!r}; expected {_COMMON_DOCS + 1} from both")

    # --- 7. _explain on a document that cannot match.
    status, unmatched = _signed_request(
        ctx, "POST", f"{base}/{_INDEX}/_explain/c000",
        body={"query": {"match": {"body": "zebra"}}})
    assert status == 200, f"_explain on a non-matching document returned HTTP {status!r}"
    assert unmatched.get("matched") is False, (
        f"_explain on a document that does not contain the term reports "
        f"matched={unmatched.get('matched')!r}: {unmatched!r}")
    assert unmatched.get("explanation", {}).get("value") == 0.0, (
        f"a non-matching _explain reports value "
        f"{unmatched.get('explanation', {}).get('value')!r}, expected 0.0")
    assert unmatched.get("explanation", {}).get("details") == [], (
        f"a non-matching _explain carries score details "
        f"{unmatched.get('explanation', {}).get('details')!r}, expected none")

    # --- 8. inline explain agrees with every hit's own score.
    inline = _search(ctx, base, {"size": 3, "explain": True,
                                 "query": {"match": {"body": "zebra common"}}})
    for hit in inline["hits"]["hits"]:
        assert abs(hit["_explanation"]["value"] - hit["_score"]) < 1e-5, (
            f"hit {hit['_id']!r} was served _score {hit['_score']!r} with an inline explanation "
            f"valued {hit['_explanation']['value']!r}")

    # --- 9. the flip. Nothing about the query or the top document changes; only the DOCUMENT SET does.
    flood = [(f"z{i:03d}", {"body": "zebra alpha bravo", "bool_body": "zebra alpha bravo",
                            "sort_id": f"zz{i:03d}"}) for i in range(_FLOOD_DOCS)]
    _bulk_load(ctx, base, _INDEX, flood)
    status, _ = _signed_request(ctx, "POST", f"{base}/{_INDEX}/_refresh")
    assert status == 200, f"the flood _refresh returned HTTP {status!r}"
    assert _count(ctx, base, "zebra") == _FLOOD_DOCS + 1, (
        f"after the flood _count reports {_count(ctx, base, 'zebra')!r} documents containing "
        f"'zebra', expected {_FLOOD_DOCS + 1}")
    flipped = _ranked(_search(ctx, base, {"size": 5,
                                          "query": {"match": {"body": "zebra common"}}}))
    assert flipped[0][0] != "zebra", (
        f"after indexing {_FLOOD_DOCS} more documents containing 'zebra' the identical query "
        f"still ranks {flipped[0][0]!r} first ({flipped!r}); the rare term's idf has collapsed, so "
        f"a scorer that reads index-wide document frequency MUST reorder -- one that scores from "
        f"the request alone cannot")
    assert flipped[0][0].startswith("c"), (
        f"after the flood the top hit is {flipped[0][0]!r}; the 'common'-only documents are now "
        f"the rarer match and must lead: {flipped!r}")
    status, reexplained = _signed_request(
        ctx, "POST", f"{base}/{_INDEX}/_explain/zebra",
        body={"query": {"match": {"body": "zebra common"}}})
    assert status == 200, f"the post-flood _explain returned HTTP {status!r}"
    assert reexplained["explanation"]["value"] < explanation["value"], (
        f"the same document's score for the same query is {reexplained['explanation']['value']!r} "
        f"after the flood and was {explanation['value']!r} before; indexing {_FLOOD_DOCS} more "
        f"documents holding its rare term must LOWER it")

    _signed_request(ctx, "DELETE", f"{base}/{_INDEX}")
    _verified_domain_teardown(ctx, domain)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
