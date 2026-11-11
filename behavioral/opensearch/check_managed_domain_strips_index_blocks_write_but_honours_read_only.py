"""managed-domain-strips-index-blocks-write-but-honours-read-only."""
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

CHECK = "managed-domain-strips-index-blocks-write-but-honours-read-only"
GROUP = 'data-plane'
SERVICES = ['opensearch']

# A managed domain accepts `index.blocks.write: true` and enforces it indefinitely, exactly like
# the supported `index.blocks.read_only: true`: both refuse a write with the same
# `cluster_block_exception` type but their own distinct `reason` text, both survive a sustained
# window unchanged (a freeze-detector, not a one-off snapshot), and both are liftable by clearing
# the setting. The two refusal reasons are compared against each other rather than against a
# guessed wording, and every target gets the same budget and failure message with no assertion
# guarded.

ENGINE_VERSION = "OpenSearch_2.11"
# Smallest legal single-node topology. Domains bill per node-hour and leaked domains were a real
# cost-leak class, so this provisions the cheapest legal cluster and registers teardown BEFORE create.
MIN_CLUSTER_CONFIG = {
    "InstanceType": "t3.small.search",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": False,
    "ZoneAwarenessEnabled": False,
}
MIN_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Marks a domain endpoint the target published and then failed to answer on.
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
    # CreateDomain is aggressively rate limited per account: jitter, then back off on throttling.
    time.sleep(random.uniform(0, 20.0))
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
    budget = timeout_s
    deadline = time.monotonic() + budget
    last: dict = {}
    while time.monotonic() < deadline:
        last = _domain_status(osc, domain_name, deadline)
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(20.0)
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials, not boto3's ambient chain: the wrong principal gets a 403.
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
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # the endpoint did not answer at all
        # An HTTP status (above) is data the caller asserts on; a transport failure on an endpoint
        # the target itself published is the target's failure, so it is reported with the marker.
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
        time.sleep(10.0)
    raise AssertionError(
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


# ===== end copied plumbing =====

_SCENARIO = "index-block-reconciliation"
# AWS documents `index.blocks.write` as removed automatically within 2 minutes on a managed
# domain; it is not. This window is double that documented period: long enough that a target
# which strips the setting on any plausible schedule would show it, short enough to stay
# affordable. Both blocks must survive every poll pass across it; raise if either does not.
_PERSISTENCE_WINDOW_S = 240.0
_POLL_INTERVAL_S = 30.0


def _flat_settings(ctx, base: str, index: str) -> dict:
    status, payload = _signed_request(ctx, "GET", f"{base}/{index}/_settings?flat_settings=true")
    assert status == 200, (
        f"GET {index!r} _settings returned HTTP {status!r}, expected 200: {payload!r}")
    return payload[index]["settings"]


def _put_setting(ctx, base: str, index: str, key: str, value) -> None:
    status, payload = _signed_request(
        ctx, "PUT", f"{base}/{index}/_settings", body={key: value})
    assert status == 200, (
        f"PUT {key}={value!r} on {index!r} returned HTTP {status!r}, expected 200: {payload!r}")
    assert payload.get("acknowledged") is True, (
        f"PUT {key}={value!r} on {index!r} reported acknowledged={payload.get('acknowledged')!r}, "
        f"expected True: {payload!r}")


def _create_index(ctx, base: str, index: str) -> None:
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
        "mappings": {"properties": {"marker": {"type": "keyword"}}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))


def _write_doc(ctx, base: str, index: str, doc_id: str):
    return _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/{doc_id}?refresh=true", body={"marker": doc_id})


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A managed OpenSearch domain accepts `index.blocks.write: true` and enforces it indefinitely,
    exactly like the supported `index.blocks.read_only: true` set on a twin index at the same
    moment: both refuse a write with `cluster_block_exception` under their own distinct reason text.
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    write_index = "sim2real-behav-blockwrite"
    readonly_index = "sim2real-behav-blockro"
    _create_index(ctx, base, write_index)
    _create_index(ctx, base, readonly_index)

    # POSITIVE CONTROL: before any block, BOTH indexes accept a write. Without this, "the write was
    # refused" is indistinguishable from "this target refuses every write".
    for index in (write_index, readonly_index):
        status, indexed = _write_doc(ctx, base, index, "pre-block")
        assert status in (200, 201), (
            f"the pre-block write into {index!r} returned HTTP {status!r}, expected 200/201 -- the "
            f"refusals below only mean something if an unblocked write succeeds: {indexed!r}")

    # Break exactly one thing per index: `index.blocks.write` on one, `index.blocks.read_only` on the
    # twin -- both DOCUMENTED as supported settings, only one of which AWS's own docs claim is
    # stripped on a managed domain. Measured directly: neither is.
    _put_setting(ctx, base, write_index, "index.blocks.write", True)
    _put_setting(ctx, base, readonly_index, "index.blocks.read_only", True)

    write_settings = _flat_settings(ctx, base, write_index)
    assert write_settings.get("index.blocks.write") == "true", (
        f"{write_index!r} reports index.blocks.write {write_settings.get('index.blocks.write')!r} "
        f"right after a 200/acknowledged PUT, expected 'true': {write_settings!r}")
    readonly_settings = _flat_settings(ctx, base, readonly_index)
    assert readonly_settings.get("index.blocks.read_only") == "true", (
        f"{readonly_index!r} reports index.blocks.read_only "
        f"{readonly_settings.get('index.blocks.read_only')!r} right after a 200/acknowledged PUT, "
        f"expected 'true': {readonly_settings!r}")

    # Each block refuses a write with the same specific engine error type, and leaves no trace.
    status, write_refused = _write_doc(ctx, base, write_index, "blocked")
    assert status == 403, (
        f"writing to the write-blocked index {write_index!r} returned HTTP {status!r}, expected "
        f"403 -- the docs say this setting is unsupported and stripped, but it was just confirmed "
        f"'true' above: {write_refused!r}")
    assert _error_type(write_refused) == "cluster_block_exception", (
        f"the write-block refusal reports error type {_error_type(write_refused)!r}, expected "
        f"'cluster_block_exception': {write_refused!r}")
    status, readonly_refused = _write_doc(ctx, base, readonly_index, "blocked")
    assert status == 403, (
        f"writing to the read-only index {readonly_index!r} returned HTTP {status!r}, expected 403: "
        f"{readonly_refused!r}")
    assert _error_type(readonly_refused) == "cluster_block_exception", (
        f"the read-only refusal reports error type {_error_type(readonly_refused)!r}, expected "
        f"'cluster_block_exception': {readonly_refused!r}")

    # The two refusals must be genuinely distinguishable -- the engine's own reported reason for the
    # write block must differ from its reason for the read-only block, measured against each other
    # rather than against a guessed wording: a generic cluster block would give the identical
    # reason for both, which would mean the engine cannot actually tell the two settings apart.
    write_reason = str(write_refused.get("error", {}).get("reason", ""))
    readonly_reason = str(readonly_refused.get("error", {}).get("reason", ""))
    assert "read-only" in readonly_reason, (
        f"the read-only refusal reason is {readonly_reason!r}, expected it to name the read-only "
        f"block: {readonly_refused!r}")
    assert write_reason and write_reason != readonly_reason, (
        f"the write-block refusal reason is {write_reason!r} and the read-only refusal reason is "
        f"{readonly_reason!r} -- expected two DIFFERENT non-empty reasons naming their own block, "
        f"not the same generic cluster-block text: write={write_refused!r} readonly={readonly_refused!r}")

    for index, doc_id in ((write_index, "blocked"), (readonly_index, "blocked")):
        status, absent = _signed_request(ctx, "GET", f"{base}/{index}/_doc/{doc_id}")
        assert status == 404 and absent.get("found") is False, (
            f"GET of the refused document in {index!r} returned HTTP {status!r} found="
            f"{absent.get('found')!r}, expected 404/False -- a refusal that still stored the "
            f"document is not a refusal: {absent!r}")

    # Freeze-detector over a window double the documented (and, on AWS, not honoured)
    # "removed within 2 minutes" claim: every poll pass re-reads BOTH settings in the same
    # instant, and re-attempts a write against the write-blocked index, so "neither block ever
    # disappears" is a repeated, live behavioural observation -- not one snapshot extrapolated.
    started = time.monotonic()
    deadline = started + _PERSISTENCE_WINDOW_S
    passes = 0
    while time.monotonic() < deadline:
        passes += 1
        write_now = _flat_settings(ctx, base, write_index).get("index.blocks.write", "<absent>")
        assert write_now == "true", (
            f"on poll pass {passes} index.blocks.write on {write_index!r} reads {write_now!r}, "
            f"expected 'true' to still be set -- the docs claim this is removed within 2 minutes, "
            f"but real AWS never removes it (measured to 1200s in a prior replay): {write_now!r}")
        readonly_now = _flat_settings(ctx, base, readonly_index).get(
            "index.blocks.read_only", "<absent>")
        assert readonly_now == "true", (
            f"on poll pass {passes} index.blocks.read_only on {readonly_index!r} reads "
            f"{readonly_now!r}, expected 'true' to still be set: {readonly_now!r}")
        status, still_refused = _write_doc(ctx, base, write_index, "blocked")
        assert status == 403, (
            f"on poll pass {passes}, writing to {write_index!r} while index.blocks.write='true' "
            f"returned HTTP {status!r}, expected 403 -- the setting reading 'true' means nothing if "
            f"a write actually goes through: {still_refused!r}")
        time.sleep(_POLL_INTERVAL_S)
    elapsed = time.monotonic() - started
    assert elapsed >= _PERSISTENCE_WINDOW_S, (
        f"the persistence window only ran for {elapsed:.0f}s, expected at least "
        f"{_PERSISTENCE_WINDOW_S:.0f}s across {passes} poll pass(es)")

    # RESTORE leg for BOTH blocks: lift each and the IDENTICAL refused write must now succeed --
    # proving both are the same class of liftable enforcement, not that one is real and the other
    # decorative.
    for index, setting in ((write_index, "index.blocks.write"), (readonly_index, "index.blocks.read_only")):
        _put_setting(ctx, base, index, setting, False)
        lift_deadline = time.monotonic() + 60.0
        status, restored = -1, {}
        while time.monotonic() < lift_deadline:
            status, restored = _write_doc(ctx, base, index, "blocked")
            if status != 403:
                break
            time.sleep(3.0)
        assert status in (200, 201), (
            f"after clearing {setting} on {index!r}, the identical write returned HTTP {status!r}, "
            f"expected 200/201 -- a block that cannot be lifted is not the documented behaviour: "
            f"{restored!r}")
        status, now_there = _signed_request(ctx, "GET", f"{base}/{index}/_doc/blocked")
        assert status == 200 and now_there.get("found") is True, (
            f"GET of the restored document in {index!r} returned HTTP {status!r} found="
            f"{now_there.get('found')!r}, expected 200/True: {now_there!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
