"""cluster-settings-flat-form-only-and-auto-create-index-false-refuses-implicit-index."""
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

CHECK = "cluster-settings-flat-form-only-and-auto-create-index-false-refuses-implicit-index"
GROUP = 'negative-classes'
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


# Marks a published domain endpoint that failed to answer as the target's failure.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"
# Marks a domain that was accepted and never converged.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """Return the "resource did not converge" error, tagged with STATE_MARKER.

    Returned rather than raised, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


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
    while time.monotonic() < deadline:
        last = _domain_status(osc, domain_name, deadline)
        if last.get("Processing") is False and last.get("Endpoint"):
            return last["Endpoint"]
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to publish a searchable endpoint: the run budget ended first; not graded")
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials (not boto3's ambient chain): signing as the wrong principal makes
    the domain's account-scoped policy 403 the request.
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
        # The endpoint was published by the target, so failing to answer on it is the target's failure.
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
    while time.monotonic() < deadline:
        status, _ = _signed_request(ctx, "GET", f"{base}/")
        if status != 403:
            return
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


_SCENARIO = "cluster-settings-auto-create"


def _persistent(ctx, base: str) -> dict:
    status, payload = _signed_request(ctx, "GET", f"{base}/_cluster/settings?flat_settings=true")
    assert status == 200, (
        f"GET _cluster/settings returned HTTP {status!r}, expected 200: {payload!r}")
    return payload.get("persistent", {})


def _read_auto_create(ctx, base: str) -> str:
    value = _persistent(ctx, base).get("action.auto_create_index")
    return str(value).lower()


def _set_auto_create(ctx, base: str, value: str) -> None:
    """PUT the setting in the FLAT form the service requires, and confirm it took."""
    status, payload = _signed_request(
        ctx, "PUT", f"{base}/_cluster/settings",
        body={"persistent": {"action.auto_create_index": value}})
    assert status == 200, (
        f"PUT _cluster/settings action.auto_create_index={value!r} in the flat form returned HTTP "
        f"{status!r}, expected 200: {payload!r}")
    assert payload.get("acknowledged") is True, (
        f"PUT _cluster/settings reported acknowledged={payload.get('acknowledged')!r}, expected "
        f"True: {payload!r}")
    deadline = time.monotonic() + _budget_s(ctx, 60.0)
    seen = None
    while time.monotonic() < deadline:
        seen = _read_auto_create(ctx, base)
        if seen == value:
            return
        time.sleep(1.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"GET _cluster/settings to report action.auto_create_index {value!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"GET _cluster/settings reports action.auto_create_index {seen!r} 60s after a 200/"
        f"acknowledged PUT of {value!r} -- a setting the target accepts and does not store is worse "
        f"than one it refuses")


def _index_implicitly(ctx, base: str, index: str):
    """Write a document into an index that was never created: the auto-creation path."""
    return _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/1?refresh=true", body={"marker": index})


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """action.auto_create_index=false stops implicit index creation, is settable only in flat form
    (the expanded form is refused and changes nothing), and setting it back restores the write.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-operations.html
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    # POSITIVE CONTROL: with auto-creation explicitly ON, an implicit write creates the index.
    _set_auto_create(ctx, base, "true")
    allowed_index = "sim2real-behav-autocreate-on"
    status, created = _index_implicitly(ctx, base, allowed_index)
    assert status in (200, 201), (
        f"with action.auto_create_index=true, writing into the absent index {allowed_index!r} "
        f"returned HTTP {status!r}, expected 200/201 -- without this the refusal below could not be "
        f"told from a target that refuses every write: {created!r}")
    status, listed = _signed_request(
        ctx, "GET", f"{base}/_cat/indices/{allowed_index}?format=json")
    assert status == 200, (
        f"_cat/indices for the auto-created index {allowed_index!r} returned HTTP {status!r}, "
        f"expected 200: {listed!r}")
    assert [row["index"] for row in listed] == [allowed_index], (
        f"_cat/indices reports {[row.get('index') for row in listed]!r} for the auto-created index, "
        f"expected exactly [{allowed_index!r}]")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{allowed_index}"))

    # Break exactly one thing.
    _set_auto_create(ctx, base, "false")

    refused_index = "sim2real-behav-autocreate-off"
    status, refused = _index_implicitly(ctx, base, refused_index)
    assert status == 404, (
        f"with action.auto_create_index=false, writing into the absent index {refused_index!r} "
        f"returned HTTP {status!r}, expected 404: {refused!r}")
    assert _error_type(refused) == "index_not_found_exception", (
        f"the refusal reports error type {_error_type(refused)!r}, expected "
        f"'index_not_found_exception': {refused!r}")
    # The reason is the generic missing-index message and does not name the switch; causality is
    # carried by the positive control above and the restore below.
    refused_reason = str(refused.get("error", {}).get("reason", ""))
    assert refused_reason == f"no such index [{refused_index}]", (
        f"the refusal reason is {refused_reason!r}, expected the exact "
        f"'no such index [{refused_index}]' -- the specific index name must be present, not just "
        f"a generic index_not_found_exception: {refused!r}")

    # Effect absent, read at the destination through a different operation.
    status, missing = _signed_request(
        ctx, "GET", f"{base}/_cat/indices/{refused_index}?format=json")
    assert status == 404, (
        f"_cat/indices for the refused index {refused_index!r} returned HTTP {status!r}, expected "
        f"404 -- a refusal that created the index anyway is not a refusal: {missing!r}")

    # The managed service refuses the EXPANDED settings form. One thing is broken (the SHAPE of the
    # request), the value it carries would be observable, and it must not land.
    # This is a managed-service proxy rejection, not an engine error: HTTP 401 with a plain
    # `{"Message": ...}` body naming the request path.
    status, expanded = _signed_request(
        ctx, "PUT", f"{base}/_cluster/settings",
        body={"persistent": {"action": {"auto_create_index": "true"}}})
    assert status == 401, (
        f"PUT _cluster/settings in the EXPANDED form returned HTTP {status!r}, expected 401 -- the "
        f"managed service documents rejecting the expanded form, and accepting it here means the "
        f"target is not enforcing that contract: {expanded!r}")
    assert expanded.get("Message") == "Your request: '/_cluster/settings' payload is not allowed.", (
        f"the expanded-form rejection body is {expanded!r}, expected the managed-service proxy "
        f"message naming the exact path '/_cluster/settings' -- not the OpenSearch engine's own "
        f"{{'error': {{'type', 'reason'}}}} shape, which would mean the engine saw the request at all")
    still_false = _read_auto_create(ctx, base)
    assert still_false == "false", (
        f"after the rejected expanded-form PUT, action.auto_create_index reads {still_false!r}, "
        f"expected 'false' -- a rejected request must not change the setting")
    status, still_refused = _index_implicitly(ctx, base, "sim2real-behav-autocreate-off2")
    assert status == 404, (
        f"after the rejected expanded-form PUT, an implicit write returned HTTP {status!r}, expected "
        f"404 -- the expanded form must not have taken effect through a side door: "
        f"{still_refused!r}")

    # RESTORE, in the flat form, and the identical refused write must now succeed.
    _set_auto_create(ctx, base, "true")
    retry_deadline = time.monotonic() + _budget_s(ctx, 60.0)
    status, restored = -1, {}
    while time.monotonic() < retry_deadline:
        status, restored = _index_implicitly(ctx, base, refused_index)
        if status != 404:
            break
        time.sleep(1.0)
    if status == 404 and _budget_spent(ctx):
        raise TimeoutError(
            f"the write into {refused_index!r} to be accepted after the restore: the run budget ended "
            f"first; not graded"
        )
    assert status in (200, 201), (
        f"after restoring action.auto_create_index=true, the identical write into {refused_index!r} "
        f"returned HTTP {status!r}, expected 200/201: {restored!r}")
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{refused_index}"))
    status, readback = _signed_request(ctx, "GET", f"{base}/{refused_index}/_doc/1")
    assert status == 200 and readback.get("found") is True, (
        f"GET of the document written after the restore returned HTTP {status!r} found="
        f"{readback.get('found')!r}, expected 200/True: {readback!r}")
    assert readback["_source"]["marker"] == refused_index, (
        f"the restored document's _source is {readback.get('_source')!r}, expected marker "
        f"{refused_index!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
