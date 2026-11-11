"""cluster-settings-put-is-refused-for-a-non-allowlisted-property."""
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

CHECK = "cluster-settings-put-is-refused-for-a-non-allowlisted-property"
GROUP = 'negative-classes'
SERVICES = ['opensearch']

# SCOPE LIMIT: Amazon OpenSearch Service's supported-operations table lists `/_cluster/settings` PUT
# as supported for six named properties only, so this check asserts just that a property OUTSIDE
# that list is refused, taking its positive control from the docs' own prescribed alternative
# (index-level `_settings`).
#
# `cluster.routing.allocation.enable` is dynamic and cluster-level in open-source OpenSearch and is
# not among the six allow-listed properties, so an OSS-backed target accepts it where a managed
# domain refuses it. The refusal is an access-layer rejection -- a bare `{"Message": ...}` body with
# HTTP 401, not the engine's `{"error": {"type": ...}}` envelope -- so no `error.type` is asserted
# here.

# ===== shared domain helpers =====

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

# An endpoint data-plane FAIL marker: the gate emulator scores any check detail containing this
# string as a real fidelity failure before its connection-error / not-implemented regexes, so a
# domain endpoint the target published and then failed to answer on is scored as the target's own
# failure rather than an environment error.
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
            # DescribeDomain shares the account's rate limit with concurrent checks; a throttled poll waits.
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
        else:
            if last.get("Processing") is False and last.get("Endpoint"):
                return last["Endpoint"]
        time.sleep(2)
    raise AssertionError(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with the credentials ctx provides (not boto3's ambient chain): signing as the wrong
    principal makes the domain's account-scoped policy 403 the request.
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


def _total(result):
    total = result.get("hits", {}).get("total")
    return total.get("value") if isinstance(total, dict) else total


def _hit_ids(result) -> list:
    return [h["_id"] for h in result["hits"]["hits"]]


# ===== end shared domain helpers =====

_SCENARIO = "cluster-settings-allowlist-boundary"

# Dynamic and cluster-level in open-source OpenSearch, and NOT one of the six `_cluster/settings`
# properties the managed service's supported-operations table names. The value is a semantic no-op
# ("all" is the default), so if a target wrongly accepts it, nothing about the cluster changes and the
# only consequence is the recorded divergence.
_FORBIDDEN_KEY = "cluster.routing.allocation.enable"
_FORBIDDEN_VALUE = "all"
_REFUSAL_MESSAGE = "Your request: '/_cluster/settings' payload is not allowed."


def _persistent(ctx, base: str) -> dict:
    status, payload = _signed_request(ctx, "GET", f"{base}/_cluster/settings?flat_settings=true")
    assert status == 200, (
        f"GET _cluster/settings returned HTTP {status!r}, expected 200 -- the GET method is documented "
        f"as supported on OpenSearch domains, and the effect-absence assertion below needs it: "
        f"{payload!r}")
    return payload.get("persistent", {})


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A `PUT /_cluster/settings` outside the documented six-property allow-list is refused with the
    exact access-layer message and changes nothing; an index-level `_settings` PUT, the docs' own
    alternative, succeeds on the same domain.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-operations.html
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    # POSITIVE CONTROL, and it is the alternative the docs themselves prescribe: an INDEX-level
    # settings write is accepted, read back, and holds the value we sent. Without this leg, "the
    # cluster API refused" is indistinguishable from "this target refuses every settings write".
    index = "sim2real-behav-clustersettings"
    status, created = _signed_request(ctx, "PUT", f"{base}/{index}", body={
        "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}}})
    assert status == 200, f"creating index {index!r} returned HTTP {status!r}: {created!r}"
    ctx.on_cleanup(lambda: _signed_request(ctx, "DELETE", f"{base}/{index}"))

    status, accepted = _signed_request(
        ctx, "PUT", f"{base}/{index}/_settings", body={"index.refresh_interval": "30s"})
    assert status == 200, (
        f"an INDEX-level settings PUT returned HTTP {status!r}, expected 200 -- this is the write the "
        f"docs point callers to when the cluster API will not take a setting, and the refusal below "
        f"only means something if this succeeds: {accepted!r}")
    assert accepted.get("acknowledged") is True, (
        f"the index-level settings PUT reported acknowledged={accepted.get('acknowledged')!r}, "
        f"expected True: {accepted!r}")
    status, index_settings = _signed_request(
        ctx, "GET", f"{base}/{index}/_settings?flat_settings=true")
    assert status == 200, f"GET {index!r} _settings returned HTTP {status!r}: {index_settings!r}"
    got_interval = index_settings[index]["settings"].get("index.refresh_interval")
    assert got_interval == "30s", (
        f"the index reports index.refresh_interval {got_interval!r} after a 200/acknowledged PUT of "
        f"'30s', expected '30s': {index_settings!r}")

    # The target's own reported value for the key we are about to try to change.
    before = _persistent(ctx, base)
    before_value = before.get(_FORBIDDEN_KEY, "<absent>")

    # THE REFUSAL: exactly one thing is wrong with this request -- the property is outside the managed
    # allow-list. The form is flat, the value is the setting's own default, and the credentials are the
    # ones that just succeeded against the index API.
    status, refused = _signed_request(
        ctx, "PUT", f"{base}/_cluster/settings",
        body={"persistent": {_FORBIDDEN_KEY: _FORBIDDEN_VALUE}})
    assert status == 401, (
        f"PUT _cluster/settings carrying the non-allow-listed property {_FORBIDDEN_KEY!r} returned "
        f"HTTP {status!r}, expected 401 -- accepting it means the target is an unrestricted cluster "
        f"rather than a managed domain: {refused!r}")
    assert refused.get("Message") == _REFUSAL_MESSAGE, (
        f"the refusal body is {refused!r}, expected the managed-service proxy message "
        f"{_REFUSAL_MESSAGE!r} naming the exact path -- not the OpenSearch engine's own "
        f"{{'error': {{'type', 'reason'}}}} shape, which would mean the engine saw the request at all")

    # EFFECT ABSENT, read through a different method on the same path.
    after = _persistent(ctx, base)
    after_value = after.get(_FORBIDDEN_KEY, "<absent>")
    assert after_value == before_value, (
        f"the persistent setting {_FORBIDDEN_KEY!r} read {before_value!r} before the refused PUT and "
        f"{after_value!r} after it; a refused request must change nothing")

    # And the positive control still holds afterwards, so the refusal did not break the domain: the
    # index-level setting we wrote is still there, and the index is still usable.
    status, still_set = _signed_request(
        ctx, "GET", f"{base}/{index}/_settings?flat_settings=true")
    assert status == 200, f"re-reading {index!r} settings returned HTTP {status!r}: {still_set!r}"
    assert still_set[index]["settings"].get("index.refresh_interval") == "30s", (
        f"after the refused cluster-settings PUT, the index reports index.refresh_interval "
        f"{still_set[index]['settings'].get('index.refresh_interval')!r}, expected the '30s' written "
        f"earlier -- the refusal must not have disturbed the index-level setting")
    status, indexed = _signed_request(
        ctx, "PUT", f"{base}/{index}/_doc/1?refresh=true", body={"marker": "after-refusal"})
    assert status in (200, 201), (
        f"indexing into {index!r} after the refused cluster-settings PUT returned HTTP {status!r}, "
        f"expected 200/201 -- the domain must still be usable: {indexed!r}")
    status, readback = _signed_request(ctx, "GET", f"{base}/{index}/_doc/1")
    assert status == 200 and readback.get("found") is True, (
        f"GET of the document written after the refusal returned HTTP {status!r} found="
        f"{readback.get('found')!r}, expected 200/True: {readback!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
