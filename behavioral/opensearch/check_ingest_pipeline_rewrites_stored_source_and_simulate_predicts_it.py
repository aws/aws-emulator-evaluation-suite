"""ingest-pipeline-rewrites-stored-source-and-simulate-predicts-it."""
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

CHECK = "ingest-pipeline-rewrites-stored-source-and-simulate-predicts-it"
GROUP = 'data-plane'
SERVICES = ['opensearch']

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology: domains bill per node-hour.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Prefix for a failure on an endpoint the target itself published, so it is graded as a fidelity
# failure rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _delete_domain_quietly(osc, domain_name: str) -> None:
    """Idempotent teardown: tolerate a domain that was never created / already deleted."""
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_min_domain(ctx, *, scenario: str, **overrides) -> str:
    """Create the cheapest legal domain, cleanup registered BEFORE the create call."""
    osc = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    ctx.on_cleanup(lambda: _delete_domain_quietly(osc, domain_name))
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig=dict(MIN_CLUSTER_CONFIG),
        EBSOptions=dict(MIN_EBS_OPTIONS),
        AccessPolicies=_account_access_policy(ctx, domain_name),
        TagList=[{"Key": "sim2real", "Value": scenario}],
    )
    kwargs.update(overrides)
    # CreateDomain is aggressively rate limited per account: back off on throttling.
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            return domain_name
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("CreateDomain still throttled after 12 attempts")


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


def _wait_searchable(ctx, domain_name: str, timeout_s: float = 1200.0) -> str:
    """Poll to Processing=False AND a published Endpoint; never a bare sleep."""
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
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to publish a searchable endpoint: the run budget ended first; not graded")
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).
    Signs with ctx's credentials, not boto3's ambient chain; the wrong principal gets a 403."""
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
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer at all
        # An HTTP status (above) is data the caller asserts on; failing to answer at all on an
        # endpoint the target itself published is the target's failure.
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _wait_data_plane_ready(ctx, base: str, timeout_s: float = 300.0) -> None:
    """Processing=False + a published Endpoint does NOT mean the data-plane authorizer has the
    access policy yet; signed requests can 403 for a while. Poll a cheap GET until it clears.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while True:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError("the domain data plane to stop answering 403: the run budget ended first; not graded")
    raise _never_ready(
        f"domain data plane still answered 403 after {timeout_s}s (last status {status})",
    )


def _error_type(payload) -> str:
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


_SCENARIO = "ingest-pipeline-transform"

# The submitted document. Every field is deliberately WRONG for the mapping until the pipeline runs:
# the title is mixed case (a keyword field, so a search for the lowercase form only matches after the
# `lowercase` processor ran), the count is a STRING (the `convert` processor must make it an integer),
# and `count_squared` / `ingested_by` do not exist at all until the pipeline adds them.
_SUBMITTED = {"title": "MiXeD Case", "count": "7"}
_EXPECTED = {"title": "mixed case", "count": 7, "count_squared": 49, "ingested_by": "sim2real"}


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An ingest pipeline set as index.default_pipeline rewrites documents (lowercase, convert,
    painless): stored _source equals the _simulate prediction, and an unconvertible doc is refused.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-operations.html
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    pipeline = "sim2real-behav-pipe"
    index = "sim2real-behav-pipe-idx"

    status, put = _signed_request(ctx, "PUT", f"{base}/_ingest/pipeline/{pipeline}", body={
        "description": "sim2real ingest transform",
        "processors": [
            {"set": {"field": "ingested_by", "value": "sim2real"}},
            {"lowercase": {"field": "title"}},
            {"convert": {"field": "count", "type": "integer"}},
            {"script": {"lang": "painless",
                        "source": "ctx.count_squared = ctx.count * ctx.count"}},
        ]})
    assert status == 200, f"creating pipeline {pipeline!r} returned HTTP {status!r}: {put!r}"
    assert put.get("acknowledged") is True, (
        f"creating pipeline {pipeline!r} reported acknowledged={put.get('acknowledged')!r}, expected "
        f"True: {put!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/_ingest/pipeline/{pipeline}"))

    # Independent read of the definition, through a different operation than the one that wrote it.
    status, fetched = _signed_request(ctx, "GET", f"{base}/_ingest/pipeline/{pipeline}")
    assert status == 200, f"GET pipeline {pipeline!r} returned HTTP {status!r}: {fetched!r}"
    processors = fetched[pipeline]["processors"]
    assert [sorted(p)[0] for p in processors] == ["set", "lowercase", "convert", "script"], (
        f"GET pipeline {pipeline!r} reports processors {[sorted(p)[0] for p in processors]!r}, "
        f"expected ['set', 'lowercase', 'convert', 'script'] in that order -- processor ORDER is "
        f"semantics here, because `script` reads the field `convert` produced: {fetched!r}")

    # `_simulate` must PREDICT the transformation without storing anything.
    status, simulated = _signed_request(
        ctx, "POST", f"{base}/_ingest/pipeline/{pipeline}/_simulate",
        body={"docs": [{"_index": index, "_id": "1", "_source": dict(_SUBMITTED)}]})
    assert status == 200, f"_simulate returned HTTP {status!r}: {simulated!r}"
    predicted = simulated["docs"][0]["doc"]["_source"]
    assert predicted == _EXPECTED, (
        f"_simulate predicts _source {predicted!r}, expected {_EXPECTED!r} -- the four processors "
        f"must lowercase the keyword, convert the count to an integer, add the set field and compute "
        f"the painless field: {simulated!r}")

    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0,
                               "default_pipeline": pipeline}},
        "mappings": {"properties": {
            "title": {"type": "keyword"},
            "count": {"type": "integer"},
            "count_squared": {"type": "integer"},
            "ingested_by": {"type": "keyword"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))

    # A plain write, with no ?pipeline= parameter: the index default must apply it.
    status, indexed = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/1?refresh=true", body=dict(_SUBMITTED))
    assert status in (200, 201), (
        f"indexing through the default pipeline returned HTTP {status!r}, expected 200/201: "
        f"{indexed!r}")

    # TERMINAL READ: a term query for the LOWERCASED keyword. A target that stored the submitted bytes
    # returns nothing here.
    status, found = _signed_request(
        ctx, "POST", f"{base}/{index}/_search",
        body={"track_total_hits": True, "query": {"term": {"title": _EXPECTED["title"]}}})
    assert status == 200, f"_search returned HTTP {status!r}: {found!r}"
    assert _total(found) == 1, (
        f"a term query for the lowercased title {_EXPECTED['title']!r} matched {_total(found)!r} "
        f"documents, expected 1 -- the `lowercase` processor did not rewrite the keyword before it "
        f"was indexed: hits={found.get('hits')!r}")
    stored = found["hits"]["hits"][0]["_source"]
    assert stored == predicted, (
        f"the STORED _source is {stored!r} but _simulate predicted {predicted!r}; the same pipeline "
        f"must produce the same document whether it is simulated or really run")
    assert stored == _EXPECTED, (
        f"the stored _source is {stored!r}, expected {_EXPECTED!r}")

    # The converted field must be a NUMBER to the engine, and the painless arithmetic must have run:
    # a numeric range filter and a term on the derived field can only match if both are true.
    status, numeric = _signed_request(
        ctx, "POST", f"{base}/{index}/_search",
        body={"track_total_hits": True, "query": {"bool": {"filter": [
            {"range": {"count": {"gte": _EXPECTED["count"], "lte": _EXPECTED["count"]}}},
            {"term": {"count_squared": _EXPECTED["count_squared"]}}]}}})
    assert status == 200, f"the numeric _search returned HTTP {status!r}: {numeric!r}"
    assert _total(numeric) == 1, (
        f"a numeric range on count=={_EXPECTED['count']} ANDed with count_squared=="
        f"{_EXPECTED['count_squared']} matched {_total(numeric)!r} documents, expected 1 -- either "
        f"`convert` left the count a string or the painless processor never computed the square: "
        f"hits={numeric.get('hits')!r}")

    # A document the pipeline CANNOT process must be refused, and must not be stored.
    status, rejected = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/2?refresh=true",
        body={"title": "Other", "count": "not-a-number"})
    assert status == 400, (
        f"indexing a document whose count cannot be converted returned HTTP {status!r}, expected 400 "
        f"-- a target that stores it has not run the pipeline: {rejected!r}")
    assert _error_type(rejected) == "illegal_argument_exception", (
        f"the pipeline failure reports error type {_error_type(rejected)!r}, expected "
        f"'illegal_argument_exception': {rejected!r}")
    assert "not-a-number" in json.dumps(rejected), (
        f"the pipeline failure does not mention the offending value 'not-a-number', so it does not "
        f"identify which processor failed: {rejected!r}")
    status, absent = _signed_request(ctx, "GET", f"{base}/{index}/_doc/2")
    assert status == 404, (
        f"GET of the refused document returned HTTP {status!r}, expected 404: {absent!r}")
    assert absent.get("found") is False, (
        f"GET of the refused document reports found={absent.get('found')!r}, expected False: "
        f"{absent!r}")
    status, counted = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200 and counted["count"] == 1, (
        f"_count reports {counted.get('count')!r} after the refusal, expected 1 -- only the first "
        f"document may exist: {counted!r}")

    # RESTORE: the same call with a convertible count succeeds and lands.
    status, accepted = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/2?refresh=true", body={"title": "Other", "count": "9"})
    assert status in (200, 201), (
        f"indexing the corrected document returned HTTP {status!r}, expected 200/201: {accepted!r}")
    status, readback = _signed_request(ctx, "GET", f"{base}/{index}/_doc/2")
    assert status == 200, f"GET of the corrected document returned HTTP {status!r}: {readback!r}"
    assert readback["_source"] == {"title": "other", "count": 9, "count_squared": 81,
                                   "ingested_by": "sim2real"}, (
        f"the corrected document's stored _source is {readback.get('_source')!r}, expected the "
        f"pipeline's rewrite with count 9 and count_squared 81")

    # The delete is mandatory anyway, so assert it: the pipeline is gone and unreadable.
    status, dropped = _signed_request(ctx, "DELETE", f"{base}/_ingest/pipeline/{pipeline}")
    assert status == 200, f"DELETE pipeline {pipeline!r} returned HTTP {status!r}: {dropped!r}"
    status, gone = _signed_request(ctx, "GET", f"{base}/_ingest/pipeline/{pipeline}")
    assert status == 404, (
        f"GET of the deleted pipeline {pipeline!r} returned HTTP {status!r}, expected 404: {gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
