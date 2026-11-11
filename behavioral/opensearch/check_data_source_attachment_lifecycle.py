"""data-source-attachment-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-source-attachment-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """AttachDataSource returns PENDING while the domain is being created and settles to ATTACHED, visible in
    describe and list; DetachDataSource removes it, and describing it then fails with
    ResourceNotFoundException and its exact message.
    """
    osv = ctx.client("opensearch")
    app_id = _create_application_no_wait(ctx)
    domain_name, domain_arn = _create_domain_no_wait(ctx)

    # The check holds the not-yet-active window itself: the domain it just created is still
    # being created. _assert_domain_still_creating reads that right before AttachDataSource, so
    # PENDING is graded while the window is verifiably open, never on an assumed creation duration.
    _assert_domain_still_creating(osv, domain_name)
    attach = _call_with_backoff(osv.attach_data_source, id=app_id, dataSourceArn=domain_arn)
    assert attach["id"] == app_id
    assert attach["dataSourceArn"] == domain_arn
    assert attach["status"] == "PENDING", f"expected PENDING while the domain is creating, got {attach['status']!r}"

    # Domain creation alone (which the attachment can't complete without) can take well over
    # 13 minutes, so allow up to 30 minutes for the domain to finish provisioning AND the
    # attachment to then settle.
    final_status = _wait_attachment_status(
        ctx, osv, app_id, domain_arn, {"ATTACHED", "FAILED"}, timeout_s=1800
    )
    assert final_status == "ATTACHED", f"attachment landed in {final_status!r} instead of ATTACHED"

    described = _call_with_backoff(osv.describe_data_source_attachment, id=app_id, dataSourceArn=domain_arn)
    assert described["dataSourceArn"] == domain_arn
    assert described["status"] == "ATTACHED"

    attachments = _list_attachment_arns(osv, app_id)
    assert domain_arn in attachments, "attachment missing from ListDataSourceAttachments"

    _call_with_backoff(osv.detach_data_source, id=app_id, dataSourceArn=domain_arn)

    deadline = time.monotonic() + _budget_s(ctx, 120)
    while domain_arn in _list_attachment_arns(osv, app_id) and time.monotonic() < deadline:
        time.sleep(2)
    if _budget_spent(ctx) and domain_arn in _list_attachment_arns(osv, app_id):
        raise TimeoutError("detached data source leaving the listing: the run budget ended first; not graded")
    assert domain_arn not in _list_attachment_arns(osv, app_id), (
        "attachment still listed after DetachDataSource"
    )

    code, message = _error(
        lambda: _call_with_backoff(osv.describe_data_source_attachment, id=app_id, dataSourceArn=domain_arn)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = (
        f"Data source attachment not found for application {app_id} and data source {domain_arn}"
    )
    assert message == expected_message, (
        f"DescribeDataSourceAttachment after detach reports {message!r}, expected {expected_message!r}"
    )


def _create_application_no_wait(ctx) -> str:
    osv = ctx.client("opensearch")
    name = ctx.unique_name("sim2real-app-")
    resp = _call_with_backoff(osv.create_application, name=name, tagList=[{"Key": "sim2real", "Value": CHECK}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(osv, app_id))
    return app_id


def _short_domain_name(ctx, tag: str) -> str:
    raw = ctx.unique_name(f"sim2real-{tag}-").lower()
    if len(raw) > 28:
        raw = raw[-28:]
    if not raw[0].isalpha():
        raw = "d" + raw[1:]
    return raw


def _create_domain_no_wait(ctx) -> str:
    osv = ctx.client("opensearch")
    domain_name = _short_domain_name(ctx, "at")
    resp = _call_with_backoff(
        osv.create_domain,
        DomainName=domain_name,
        # Pinning to a known engine version (instead of letting CreateDomain default to
        # whatever the latest release happens to be) matters here: the default has been
        # observed taking noticeably longer to provision than this pinned version, which
        # is the difference between comfortably finishing domain creation + the
        # attachment settling within the harness's wall-clock budget and blowing through
        # it.
        EngineVersion="OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        # Tagged at creation so tag-based cleanup can find leaked domains: it discovers what
        # to delete through the Resource Groups Tagging API and sees nothing else.
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    domain_arn = resp["DomainStatus"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_domain(osv, domain_name))
    return domain_name, domain_arn


def _assert_domain_still_creating(osv, domain_name) -> None:
    status = _call_with_backoff(osv.describe_domain, DomainName=domain_name)["DomainStatus"]
    assert status.get("Processing") is True and status.get("Endpoint") is None, (
        f"domain {domain_name} left its creating window while the check held it: "
        f"Processing={status.get('Processing')!r}, Endpoint={status.get('Endpoint')!r}"
    )



def _call_with_backoff(fn, *args, retries: int = 6, base_delay: float = 3.0, **kwargs):
    """Retry on ThrottlingException with exponential backoff.

    Several checks in this suite create/poll OpenSearch domains and applications
    concurrently, which can exceed the account's request rate for describe/list calls
    and exhaust botocore's own retry budget. Back off and retry those transient
    throttling errors ourselves instead of silently burning through the harness's
    wall-clock budget on hidden botocore retries or failing the check outright.
    """
    last_err = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ThrottlingException":
                raise
            last_err = err
            if attempt < retries - 1:
                time.sleep(base_delay * (2 ** attempt))
    raise last_err


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_attachment_status(ctx, osv, app_id: str, data_source_arn: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 2.0) -> str:
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _call_with_backoff(osv.describe_data_source_attachment, id=app_id, dataSourceArn=data_source_arn)["status"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"attachment reaching {terminal!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"attachment status stuck at {last!r} after {timeout_s}s, never reached {terminal!r}"
    )


def _list_attachment_arns(osv, app_id: str) -> set[str]:
    arns: set[str] = set()
    token = None
    while True:
        kwargs = {"id": app_id}
        if token:
            kwargs["nextToken"] = token
        resp = _call_with_backoff(osv.list_data_source_attachments, **kwargs)
        for a in resp.get("attachments", []):
            arns.add(a["dataSourceArn"])
        token = resp.get("nextToken")
        if not token:
            break
    return arns



def _safe_delete_application(osv, app_id: str) -> None:
    try:
        osv.delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_domain(osv, domain_name: str) -> None:
    try:
        osv.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
