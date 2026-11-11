"""disabled-refresh-interval-hides-document-from-search-until-refresh."""
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

CHECK = "disabled-refresh-interval-hides-document-from-search-until-refresh"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# ===== shared domain helpers =====

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology; teardown is registered before the create call so a failed
# create never leaves a domain behind.
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

    Signs with the credentials ctx wired for THIS account (not boto3's ambient chain):
    signing as the wrong principal makes the domain's account-scoped policy 403 the request.
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
        # urllib reports it in wording that reads as a local network problem. The endpoint here was
        # published by the target itself, so failing to answer on it is the target's failure.
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
    """OpenSearch engine errors carry {'error': {'type': ..., 'reason': ...}, 'status': n}."""
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("type") or "")
    return ""


def _error_reason(payload) -> str:
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return str(error.get("reason") or "")
    return ""


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


# ===== end shared domain helpers =====

_SCENARIO = "refresh-visibility-window"
# >= 3x the 1 s default automatic refresh interval the AWS docs name, so a target that merely
# refreshes on the default cadence cannot pass the freeze leg by being slow.
_FREEZE_WINDOW_S = 4.0


def _search_all(ctx, base: str, index: str) -> dict:
    status, result = _signed_request(
        ctx, "POST", f"{base}/{index}/_search",
        body={"size": 10, "track_total_hits": True, "query": {"match_all": {}}})
    assert status == 200, f"_search on {index!r} returned HTTP {status!r}, expected 200: {result!r}"
    return result


def _count(ctx, base: str, index: str) -> int:
    status, result = _signed_request(ctx, "GET", f"{base}/{index}/_count")
    assert status == 200, f"_count on {index!r} returned HTTP {status!r}, expected 200: {result!r}"
    return result["count"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With `index.refresh_interval: -1`, a `?refresh=false` write is realtime-readable by id yet
    invisible to `_search`/`_count` across repeated reads, until a later `?refresh=true` write
    forces a per-shard refresh that reveals both documents at once.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    index = "sim2real-behav-refresh"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            # The whole subject of the check: automatic refresh OFF.
            "refresh_interval": "-1",
        }},
        "mappings": {"properties": {"marker": {"type": "keyword"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))

    # The control is DEMONSTRATED, not assumed: the engine must report the interval it accepted.
    status, settings = _signed_request(
        ctx, "GET", f"{base}/{index}/_settings?flat_settings=true")
    assert status == 200, f"reading {index!r} settings returned HTTP {status!r}: {settings!r}"
    got_interval = settings[index]["settings"].get("index.refresh_interval")
    assert got_interval == "-1", (
        f"index {index!r} reports index.refresh_interval {got_interval!r}, expected '-1' -- without "
        f"the automatic refresh actually disabled the invisibility below would prove nothing: "
        f"{settings!r}")

    # A document written with the DEFAULT refresh policy (?refresh=false).
    status, indexed = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/withheld?refresh=false",
        body={"marker": "withheld"})
    assert status in (200, 201), (
        f"indexing the withheld document returned HTTP {status!r}, expected 200/201: {indexed!r}")
    assert indexed.get("result") == "created", (
        f"indexing the withheld document reported result {indexed.get('result')!r}, expected "
        f"'created': {indexed!r}")

    # POSITIVE CONTROL, same wiring, same instant: the realtime GET-by-id must find it. This is what
    # makes the zero-hit searches below evidence of a refresh window rather than a lost write.
    status, fetched = _signed_request(ctx, "GET", f"{base}/{index}/_doc/withheld")
    assert status == 200, (
        f"realtime GET of the withheld document returned HTTP {status!r}, expected 200 -- the "
        f"document must be IN the cluster for the search-invisibility legs to mean anything: "
        f"{fetched!r}")
    assert fetched.get("found") is True, (
        f"realtime GET reports found={fetched.get('found')!r} for the withheld document, expected "
        f"True: {fetched!r}")
    assert fetched["_source"]["marker"] == "withheld", (
        f"realtime GET returned _source {fetched.get('_source')!r}, expected marker 'withheld'")

    # FREEZE DETECTOR: N consecutive reads across a window >= 3x the documented default refresh
    # cadence must all return the SAME zero answer, on two independent observables.
    # The window always spans at least three read pairs, however slow each read is.
    started = time.monotonic()
    reads = 0
    while time.monotonic() - started < _FREEZE_WINDOW_S or reads < 3:
        result = _search_all(ctx, base, index)
        hidden_total = _total(result)
        assert hidden_total == 0, (
            f"_search on {index!r} reports {hidden_total!r} hits {time.monotonic() - started:.1f}s "
            f"after a ?refresh=false write into an index with refresh_interval=-1, expected 0 -- the "
            f"document is realtime-readable by id, so a searchable document here means the target "
            f"ignores the refresh contract: hits={result.get('hits')!r}")
        hidden_count = _count(ctx, base, index)
        assert hidden_count == 0, (
            f"_count on {index!r} reports {hidden_count!r}, expected 0 -- a second independent "
            f"observable of the same invisibility")
        reads += 1
        time.sleep(0.5)

    # REPAIR: force a refresh through a LATER write. A refresh is per-shard, so this must make the
    # withheld document searchable too -- the leg a target that special-cases ?refresh=true for its
    # own document alone cannot pass.
    status, forced = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/forced?refresh=true", body={"marker": "forced"})
    assert status in (200, 201), (
        f"indexing the forcing document with ?refresh=true returned HTTP {status!r}: {forced!r}")

    result = _search_all(ctx, base, index)
    visible_total = _total(result)
    assert visible_total == 2, (
        f"after a ?refresh=true write, _search reports {visible_total!r} hits, expected 2 -- a "
        f"refresh is per-shard, so the earlier ?refresh=false document must become searchable in the "
        f"same operation: hits={result.get('hits')!r}")
    assert sorted(_hit_ids(result)) == ["forced", "withheld"], (
        f"_search returned ids {sorted(_hit_ids(result))!r}, expected ['forced', 'withheld']")
    revealed_count = _count(ctx, base, index)
    assert revealed_count == 2, (
        f"_count reports {revealed_count!r} after the forcing refresh, expected 2")

    # The delete is already mandatory, so it is a free negative: gone, and unusable by id.
    status, deleted = _signed_request(ctx, "DELETE", f"{base}/{index}")
    assert status == 200, f"DELETE of index {index!r} returned HTTP {status!r}: {deleted!r}"
    status, gone = _signed_request(ctx, "GET", f"{base}/{index}/_doc/withheld")
    assert status == 404, (
        f"GET of a document in the deleted index {index!r} returned HTTP {status!r}, expected 404: "
        f"{gone!r}")
    assert _error_type(gone) == "index_not_found_exception", (
        f"GET after DELETE reports error type {_error_type(gone)!r}, expected "
        f"'index_not_found_exception': {gone!r}")
    expected_reason = f"no such index [{index}]"
    assert _error_reason(gone) == expected_reason, (
        f"GET after DELETE reports reason {_error_reason(gone)!r}, expected {expected_reason!r}: "
        f"{gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
