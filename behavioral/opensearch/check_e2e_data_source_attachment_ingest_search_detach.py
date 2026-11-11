"""e2e-data-source-attachment-ingest-search-detach."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-data-source-attachment-ingest-search-detach"
GROUP = "e2e"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A domain attached as an application data source reaches ATTACHED and is listed; a doc indexed
    on it is searchable; detaching removes the attachment everywhere but leaves the domain's data.
    """
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx)
    domain_status = _create_minimal_domain(ctx, domain_name)
    domain_arn = domain_status["ARN"]
    endpoint = domain_status["Endpoint"]

    app_id = _create_active_application(ctx)

    attached = client.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    assert attached["dataSourceArn"] == domain_arn, (
        f"attach_data_source echoed dataSourceArn={attached['dataSourceArn']!r}, expected {domain_arn!r}"
    )

    final_attach = _poll_attachment_status(ctx, app_id, domain_arn, {"ATTACHED"}, {"FAILED"}, timeout_s=300.0)
    assert final_attach["status"] == "ATTACHED", (
        f"expected attachment status ATTACHED, got {final_attach['status']!r}: {final_attach!r}"
    )

    listed = client.list_data_source_attachments(id=app_id).get("attachments", [])
    match = next((a for a in listed if a["dataSourceArn"] == domain_arn), None)
    assert match is not None, f"attached data source missing from ListDataSourceAttachments: {listed!r}"
    assert match["status"] == "ATTACHED", f"expected ListDataSourceAttachments status ATTACHED, got {match['status']!r}: {match!r}"

    _index_and_search(ctx, endpoint, index=f"{domain_name}-idx")

    client.detach_data_source(id=app_id, dataSourceArn=domain_arn)

    code, message = _poll_describe_gone(ctx, app_id, domain_arn, timeout_s=180.0)
    assert code == "ResourceNotFoundException", f"attachment record was not removed after detach: {code!r}"
    expected = f"Data source attachment not found for application {app_id} and data source {domain_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed_after = client.list_data_source_attachments(id=app_id).get("attachments", [])
    assert not any(a["dataSourceArn"] == domain_arn for a in listed_after), (
        f"detached data source still present in ListDataSourceAttachments: {listed_after!r}"
    )

    # Detaching the application-side view must not delete the domain's own indexed data.
    _assert_still_searchable(ctx, endpoint, index=f"{domain_name}-idx")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _domain_name(ctx) -> str:
    raw = ctx.unique_name("sim2r-att-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:28]


def _app_name(ctx) -> str:
    raw = ctx.unique_name("sim2real-att-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:30]


def _create_minimal_domain(ctx, name):
    client = ctx.client("opensearch")
    client.create_domain(
        DomainName=name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return _wait_domain_active(ctx, name)


def _wait_domain_active(ctx, name, timeout_s=1800.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s (last={status!r})")


def _create_active_application(ctx) -> str:
    client = ctx.client("opensearch")
    name = _app_name(ctx)
    created = client.create_application(name=name, tagList=[{"Key": "sim2real", "Value": CHECK}])
    app_id = created["id"]
    ctx.on_cleanup(lambda: client.delete_application(id=app_id))
    deadline = time.monotonic() + _budget_s(ctx, 600.0)
    last = None
    while time.monotonic() < deadline:
        got = client.get_application(id=app_id)
        last = got.get("status")
        if last == "ACTIVE":
            return app_id
        if last == "FAILED":
            raise AssertionError(f"application {app_id} failed to become active: {got!r}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"application {app_id} to reach ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"application {app_id} did not reach ACTIVE within 600s (last={last!r})")


def _poll_attachment_status(ctx, app_id, data_source_arn, ok_statuses, terminal_bad_statuses, timeout_s=300.0):
    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = client.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)
        status = last.get("status")
        if status in ok_statuses:
            return last
        if status in terminal_bad_statuses:
            raise AssertionError(f"attachment reached bad status {status!r}: {last!r}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"attachment to reach {ok_statuses}: the run budget ended first; not graded")
    raise AssertionError(f"attachment did not reach {ok_statuses} within {timeout_s}s (last={last!r})")


def _poll_describe_gone(ctx, app_id, data_source_arn, timeout_s=180.0):
    """Poll DescribeDataSourceAttachment until it raises; return that error's (code, message).
    Raises if the describe still succeeds at the deadline."""
    from botocore.exceptions import ClientError

    client = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = client.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError("attachment to stop being described: the run budget ended first; not graded")
    raise AssertionError(f"attachment still described {timeout_s}s after detach: {last!r}")


def _signed_json(ctx, method, url, body=None):
    """SigV4 ('es') request to the domain endpoint, signed with the opensearch client's
    credentials and sent with stdlib urllib."""
    import json
    import urllib.error
    import urllib.request

    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest

    creds = ctx.client("opensearch")._request_signer._credentials
    if creds is None:
        raise AssertionError("no AWS credentials available to sign OpenSearch data-plane requests")
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    aws_req = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(creds.get_frozen_credentials(), "es", ctx.region).add_auth(aws_req)
    req = urllib.request.Request(url, data=data, method=method, headers=dict(aws_req.headers))
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except ValueError:
            return exc.code, {"raw": raw}


def _base_url(ctx, endpoint):
    return ctx.endpoint_url(endpoint).rstrip("/")


def _wait_data_plane_authorized(ctx, base, timeout_s=300.0):
    """A published Endpoint does not mean the data-plane authorizer has the access policy yet;
    poll a signed GET until it stops answering 403."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status, _ = _signed_json(ctx, "GET", f"{base}/")
        if status != 403:
            return
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError("the signed data-plane GET to stop answering 403: the run budget ended first; not graded")
    raise AssertionError(f"signed data-plane GET still answered {status} after {timeout_s}s")


def _search_total(ctx, base, index):
    status, result = _signed_json(
        ctx, "POST", f"{base}/{index}/_search", {"query": {"match": {"val": "sim2real-attach"}}}
    )
    assert status == 200, f"_search on {index} answered HTTP {status}: {result!r}"
    total = result.get("hits", {}).get("total", {})
    return total.get("value", 0) if isinstance(total, dict) else total


def _index_and_search(ctx, endpoint, *, index):
    base = _base_url(ctx, endpoint)
    _wait_data_plane_authorized(ctx, base)
    status, body = _signed_json(ctx, "PUT", f"{base}/{index}/_doc/1?refresh=true", {"val": "sim2real-attach"})
    assert status in (200, 201), f"indexing a document answered HTTP {status}: {body!r}"
    total = _search_total(ctx, base, index)
    assert total >= 1, f"indexed document was not searchable through the attached domain (total={total!r})"


def _assert_still_searchable(ctx, endpoint, *, index):
    base = _base_url(ctx, endpoint)
    try:
        total = _search_total(ctx, base, index)
        assert total >= 1, f"domain data disappeared after detaching the application view (total={total!r})"
    finally:
        try:
            _signed_json(ctx, "DELETE", f"{base}/{index}")
        except Exception:  # noqa: BLE001 -- best-effort cleanup; the domain itself is torn down later
            pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
