"""nodes-apis-redact-service-internals-while-reporting-the-configured-topology."""
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

CHECK = "nodes-apis-redact-service-internals-while-reporting-the-configured-topology"
GROUP = 'representation'
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

# Marks a published domain endpoint that failed to answer as a target failure, not an environment one.
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
        time.sleep(2.0)
    raise _never_ready(
        f"domain {domain_name} did not publish a searchable endpoint within {budget}s "
        f"(Processing={last.get('Processing')}, Endpoint={last.get('Endpoint')})",
    )


def _signed_request(ctx, method, url, *, body=None, raw=None, content_type="application/json"):
    """SigV4-signed ('es') HTTPS request to a domain endpoint -> (status, parsed_json).

    Signs with ctx's credentials, not boto3's ambient chain: the account-scoped policy 403s others.
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
        # The endpoint was published by the target itself, so failing to answer is its failure.
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
        time.sleep(2.0)
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


_SCENARIO = "nodes-api-redaction"
# Documented as "information that exposes service internals"; read per node, so partial redaction
# is caught.
_REDACTED_OS_KEYS = ("name", "version", "pretty_name")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """`_nodes` and `_nodes/stats/fs` keep processor counts, fs totals and one node per instance, but
    redact the OS name/version and the filesystem data path, as the managed service documents.

    Reference: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-operations.html
    """
    domain = _create_min_domain(ctx, scenario=_SCENARIO)
    osc = ctx.client("opensearch")
    base = ctx.endpoint_url(_wait_searchable(ctx, domain))
    _wait_data_plane_ready(ctx, base)

    status, nodes_payload = _signed_request(ctx, "GET", f"{base}/_nodes")
    assert status == 200, f"GET _nodes returned HTTP {status!r}, expected 200: {nodes_payload!r}"
    nodes = nodes_payload["nodes"]
    assert len(nodes) >= 1, (
        f"_nodes reports {len(nodes)!r} nodes, expected at least 1 -- an empty node list would make "
        f"every absence assertion below vacuous: {nodes_payload!r}")

    for node_id, node in nodes.items():
        os_section = node["os"]
        # POSITIVE CONTROL, in the same object: the section exists and carries real data.
        processors = os_section["available_processors"]
        assert isinstance(processors, int) and processors >= 1, (
            f"node {node_id!r} reports os.available_processors {processors!r}, expected a positive "
            f"integer -- the os section must be populated for its redactions to mean anything: "
            f"{os_section!r}")
        leaked = [key for key in _REDACTED_OS_KEYS if key in os_section]
        assert leaked == [], (
            f"node {node_id!r} exposes os keys {leaked!r} in _nodes; Amazon OpenSearch Service "
            f"documents redacting the operating system name and version, so a response carrying them "
            f"is the open-source shape rather than the managed one: {os_section!r}")

    status, stats_payload = _signed_request(ctx, "GET", f"{base}/_nodes/stats/fs")
    assert status == 200, (
        f"GET _nodes/stats/fs returned HTTP {status!r}, expected 200: {stats_payload!r}")
    stats_nodes = stats_payload["nodes"]
    assert set(stats_nodes) == set(nodes), (
        f"_nodes/stats/fs reports node ids {sorted(stats_nodes)!r} but _nodes reported "
        f"{sorted(nodes)!r}; the same cluster must describe the same nodes through both APIs")

    for node_id, node in stats_nodes.items():
        fs_section = node["fs"]
        total_bytes = fs_section["total"]["total_in_bytes"]
        assert total_bytes > 0, (
            f"node {node_id!r} reports fs.total.total_in_bytes {total_bytes!r}, expected a positive "
            f"byte count for a 10 GiB gp3 volume -- the fs section must be populated for its "
            f"redaction to mean anything: {fs_section!r}")
        # Checked on the serialised text so a target omitting fs.data entirely is still covered.
        serialised = json.dumps(fs_section)
        assert '"path"' not in serialised, (
            f"node {node_id!r} exposes a filesystem path key in _nodes/stats/fs; Amazon OpenSearch "
            f"Service documents redacting the file system data path, so this response leaks a "
            f"service internal: {serialised[:400]!r}")

    # The join back to the control plane: redaction must not have become "answer with nothing".
    left = ctx.time_left()
    described = _domain_status(osc, domain, time.monotonic() + (120.0 if left is None else min(120.0, left)))
    declared = described["ClusterConfig"]
    assert declared.get("InstanceCount") == MIN_CLUSTER_CONFIG["InstanceCount"], (
        f"the control plane reports InstanceCount {declared.get('InstanceCount')!r} for a domain "
        f"created with {MIN_CLUSTER_CONFIG['InstanceCount']!r}, so the node-count comparison has "
        f"nothing to join to: {declared!r}")
    assert len(nodes) == declared["InstanceCount"], (
        f"_nodes reports {len(nodes)!r} nodes but the control plane declares InstanceCount "
        f"{declared['InstanceCount']!r} with no dedicated masters; the redacted response must still "
        f"describe the topology that was ordered")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
