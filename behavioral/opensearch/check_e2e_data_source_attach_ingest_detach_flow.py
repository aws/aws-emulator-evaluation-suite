"""e2e-data-source-attach-ingest-detach-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-data-source-attach-ingest-detach-flow"
GROUP = "e2e"
SERVICES = ["opensearch"]

# Prefix of the failure raised when a domain endpoint the target published does not answer, so
# that outcome reads as the target's failure rather than as a local network problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """An OpenSearch domain attached as an application data source reaches ATTACHED, serves a real
    index/search through its own endpoint, and once detached is gone from ListDataSourceAttachments
    with DescribeDataSourceAttachment answering ResourceNotFoundException.
    """
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    domain_name = ctx.unique_name("sim2real-ds-")[:28].rstrip("-") or "sim2real-ds-fallback"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "es:*",
                "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{domain_name}/*",
            }
        ],
    }
    osc.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=json.dumps(policy),
        TagList=[{"Key": "sim2real-audit", "Value": CHECK}],
    )["DomainStatus"]
    ctx.on_cleanup(lambda: _delete_domain_quiet(osc, domain_name))
    domain_status = _wait_domain_active(osc, domain_name, timeout_s=1800)
    domain_arn = domain_status["ARN"]
    endpoint = domain_status["Endpoint"]

    app_name = ctx.unique_name("sim2real-app-")[:30].rstrip("-") or "sim2realappfallback"
    try:
        app = osc.create_application(name=app_name, tagList=[{"Key": "sim2real-audit", "Value": CHECK}])
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch application feature (direct-query/UI applications) is not "
                "enabled for this account/region"
            )
        raise
    app_id = app["id"]
    ctx.on_cleanup(lambda: _delete_application_quiet(osc, app_id))
    _wait_application_active(osc, app_id, timeout_s=300)

    attach = osc.attach_data_source(
        id=app_id,
        dataSourceArn=domain_arn,
        workspaceConfiguration={"name": "sim2real-ws", "workspaceType": "SEARCH"},
    )
    assert attach["dataSourceArn"] == domain_arn, f"expected dataSourceArn {domain_arn}, got {attach['dataSourceArn']!r}"
    assert attach["status"] in ("PENDING", "ATTACHED"), f"unexpected initial attach status {attach['status']!r}"

    _wait_attachment_status(osc, app_id, domain_arn, "ATTACHED", timeout_s=300)

    attachments = osc.list_data_source_attachments(id=app_id)["attachments"]
    assert any(a["dataSourceArn"] == domain_arn and a["status"] == "ATTACHED" for a in attachments), attachments

    _ingest_and_search(ctx, endpoint, index=f"{domain_name}-idx")

    osc.detach_data_source(id=app_id, dataSourceArn=domain_arn)
    _wait_attachment_absent(osc, app_id, domain_arn, timeout_s=180)

    code, message = _error_from_call(lambda: osc.describe_data_source_attachment(id=app_id, dataSourceArn=domain_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException describing a detached attachment, got {code!r}"
    )
    expected = f"Data source attachment not found for application {app_id} and data source {domain_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== shared domain helpers =====
def _wait_domain_active(osc, domain_name, timeout_s=1800.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last["Processing"] is False and last.get("Endpoint"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never became Active with a published Endpoint within {timeout_s}s: {last}")


def _signed_json_request(ctx, method: str, url: str, body=None):
    """Send a SigV4-signed ('es') HTTPS request to a domain endpoint.

    Signs with botocore (always available) and sends with stdlib urllib so the
    check needs no third-party HTTP client.
    """
    import json as _json
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    # Sign with the SAME credentials ctx wired for THIS account — NOT boto3's ambient
    # chain. Signing with the ambient account makes the data-plane request come from the wrong
    # principal, which the domain's account-scoped ":root" access policy 403s.
    signer_creds = ctx.client("opensearch")._request_signer._credentials
    if signer_creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    frozen = signer_creds.get_frozen_credentials()

    data = _json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(frozen, "es", ctx.region).add_auth(aws_req)

    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, (_json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            parsed = _json.loads(raw)
        except ValueError:
            parsed = {"raw": raw}
        return exc.code, parsed
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
        raise AssertionError(
            f"{DATAPLANE_MARKER}: signed {method} to the domain endpoint did not complete: "
            f"{type(exc).__name__}: {exc}"
        ) from exc


def _ingest_and_search(ctx, endpoint, *, index):
    """Prove the attached domain is actually usable: index a real document through its
    data-plane endpoint and search it back. This is the "ingest" the flow is named for —
    without it, the check would only ever exercise the control-plane attachment record."""
    base = ctx.endpoint_url(endpoint)
    # Control-plane ACTIVE + a published Endpoint does not mean the data-plane authorizer has
    # picked up the access policy yet; a signed request can 403 for a while after. Poll a
    # lightweight signed GET until it stops returning 403 before exercising index/search.
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        status, _ = _signed_json_request(ctx, "GET", f"{base}/")
        if status != 403:
            break
        time.sleep(2)

    doc = {"title": "sim2real", "marker": index}
    status, _ = _signed_json_request(ctx, "PUT", f"{base}/{index}/_doc/1", doc)
    assert status in (200, 201), f"{DATAPLANE_MARKER}: indexing document failed with HTTP {status}"

    status, _ = _signed_json_request(ctx, "POST", f"{base}/{index}/_refresh")
    assert status == 200, f"{DATAPLANE_MARKER}: index refresh failed with HTTP {status}"

    query = {"query": {"match": {"title": "sim2real"}}}
    status, result = _signed_json_request(ctx, "POST", f"{base}/{index}/_search", query)
    assert status == 200, f"{DATAPLANE_MARKER}: _search failed with HTTP {status}: {result}"
    total = result.get("hits", {}).get("total", {})
    total_value = total.get("value") if isinstance(total, dict) else total
    assert total_value and total_value >= 1, f"{DATAPLANE_MARKER}: search returned no hits: {result.get('hits')}"
    hits = result["hits"]["hits"]
    assert any(hit.get("_source", {}).get("marker") == index for hit in hits), (
        f"indexed document not found in search hits: {hits}"
    )

    try:
        _signed_json_request(ctx, "DELETE", f"{base}/{index}")
    except Exception:  # noqa: BLE001 -- best-effort cleanup; the domain itself is torn down later
        pass


def _wait_application_active(osc, app_id, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.get_application(id=app_id)["status"]
        if last == "ACTIVE":
            return
        if last == "FAILED":
            raise AssertionError(f"application {app_id} failed to become ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s: last={last}")


def _wait_attachment_status(osc, app_id, data_source_arn, target, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)["status"]
        if last == target:
            return
        if last == "FAILED":
            raise AssertionError(f"attachment for {data_source_arn} FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"attachment never reached {target} within {timeout_s}s: last={last}")


def _wait_attachment_absent(osc, app_id, data_source_arn, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        attachments = osc.list_data_source_attachments(id=app_id)["attachments"]
        if not any(a["dataSourceArn"] == data_source_arn for a in attachments):
            return
        time.sleep(interval_s)
    raise AssertionError(f"attachment for {data_source_arn} still listed after detach")


def _delete_domain_quiet(osc, domain_name):
    try:
        osc.delete_domain(DomainName=domain_name)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise


def _delete_application_quiet(osc, app_id):
    try:
        osc.delete_application(id=app_id)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise


def _error_code_from_exc(exc):
    resp = getattr(exc, "response", None)
    if not resp:
        return None
    return resp.get("Error", {}).get("Code")


def _error_from_call(fn):
    """Call fn() and return the (code, message) of the ClientError it raises, or raise if it
    succeeds — success on an already-detached attachment is the defect under test, not a
    result to fold into a falsy sentinel."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        code = _error_code_from_exc(exc)
        if code is None:
            raise
        return code, exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to fail with ResourceNotFoundException, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
