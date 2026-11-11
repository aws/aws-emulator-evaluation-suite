"""concurrent-start-migration-independent-domains."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-start-migration-independent-domains"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent StartMigration calls on two applications, each with an ATTACHED domain, are each
    rejected with ValidationException (the source must be an aoss collection ARN) and neither
    application is left holding a migration record."""
    opensearch = ctx.client("opensearch")

    # Wait for both domains in parallel to avoid paying the ~20 min creation latency twice.
    domain_a, arn_a = _create_minimal_domain(ctx, "ma")
    domain_b, arn_b = _create_minimal_domain(ctx, "mb")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda n: _wait_domain_active(ctx, n), [domain_a, domain_b]))

    app_a = _create_application(ctx, "ma")
    app_b = _create_application(ctx, "mb")

    opensearch.attach_data_source(id=app_a, dataSourceArn=arn_a)
    opensearch.attach_data_source(id=app_b, dataSourceArn=arn_b)
    with ThreadPoolExecutor(max_workers=2) as pool:
        attach_states = list(
            pool.map(lambda args: _wait_attachment_status(ctx, *args), [(app_a, arn_a), (app_b, arn_b)])
        )
    if any(s not in ("ATTACHED", "FAILED") for s in attach_states) and _budget_spent(ctx):
        raise TimeoutError(
            f"both data-source attachments to settle (got {attach_states!r}): the run budget ended first; "
            f"not graded"
        )
    # Both attachments must be live, or the rejection below could be blamed on a missing
    # attachment (which is ResourceNotFoundException, a different class) instead of on the
    # datasourceArn constraint this check is about.
    assert attach_states == ["ATTACHED", "ATTACHED"], (
        f"expected both data-source attachments to reach ATTACHED, got {attach_states!r}"
    )

    def _start(app_id, arn, tag):
        return opensearch.start_migration(
            applicationId=app_id,
            migrationOptions={
                "source": {"datasourceArn": arn},
                "workspace": {"createWorkspace": True, "name": f"sim2real-ws-{tag}", "type": "SEARCH"},
            },
        )

    # The refusal is per-request validation, so simultaneous requests must not share a verdict.
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_outcome, _start, app_a, arn_a, "a")
        fut_b = pool.submit(_outcome, _start, app_b, arn_b, "b")
        code_a, msg_a = fut_a.result()
        code_b, msg_b = fut_b.result()

    for tag, arn, code, msg in (("a", arn_a, code_a, msg_a), ("b", arn_b, code_b, msg_b)):
        assert code == "ValidationException", (
            f"application {tag}: expected a domain-ARN migration source to be rejected with "
            f"ValidationException even under concurrency, got {code!r} ({msg!r})"
        )
        expected = (
            f"1 validation error detected: Value '{arn}' at 'migrationOptions.source.datasourceArn' "
            "failed to satisfy constraint: Member must satisfy regular expression pattern: "
            "arn:aws[a-z\\-]*:aoss:[a-z0-9\\-]+:[0-9]{12}:collection/[a-z0-9]+"
        )
        assert msg == expected, (
            f"application {tag}: expected the rejection to name the datasourceArn/collection-ARN "
            f"constraint, got {msg!r}"
        )

    # No leakage either way: a rejected StartMigration must leave NO migration record on either
    # application, so neither request can have been half-applied or attributed to its neighbour.
    for tag, app_id in (("a", app_a), ("b", app_b)):
        migrations = opensearch.list_migrations(applicationId=app_id).get("migrations", [])
        assert migrations == [], (
            f"application {tag} ({app_id}) holds a migration record after a rejected, concurrent "
            f"StartMigration: {migrations!r}"
        )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")


def _throttled(fn, **kwargs):
    """fn(**kwargs), retried with exponential backoff (2-30 s, 8 attempts) while throttled."""
    for attempt in range(8):
        try:
            return fn(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in _THROTTLE_CODES or attempt == 7:
                raise
        time.sleep(min(30.0, 2.0 * 2**attempt))
    raise AssertionError("unreachable")


def _short_name(ctx, tag: str, maxlen: int) -> str:
    raw = ctx.unique_name(f"os{tag}").lower()
    raw = re.sub(r"[^a-z0-9-]", "-", raw)
    raw = re.sub(r"-+", "-", raw).strip("-")
    if len(raw) > maxlen:
        keep_tail = maxlen - 6
        raw = raw[:6] + raw[-keep_tail:]
    if not raw or not raw[0].isalpha():
        raw = "a" + raw[1:]
    return raw[:maxlen]


def _create_minimal_domain(ctx, tag: str):
    opensearch = ctx.client("opensearch")
    name = _short_name(ctx, tag, 28)
    resp = opensearch.create_domain(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name, resp["DomainStatus"]["ARN"]


def _safe_delete_domain(ctx, name: str) -> None:
    try:
        ctx.client("opensearch").delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name: str, timeout_s: float = 2700, interval_s: float = 5):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = _throttled(opensearch.describe_domain, DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return status
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {name} to become active: the run budget ended first; not graded")
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s")


def _create_application(ctx, tag: str) -> str:
    opensearch = ctx.client("opensearch")
    name = _short_name(ctx, tag, 30)
    try:
        resp = opensearch.create_application(
            name=name,
            tagList=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real", "Value": CHECK}],
        )
    except Exception as exc:  # noqa: BLE001
        code = exc.response["Error"]["Code"] if hasattr(exc, "response") else None
        if code == "DisabledOperationException":
            raise AssertionError(
                "OpenSearch Applications feature is not enabled for this account/region"
            ) from exc
        raise
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe_delete_application(ctx, app_id))
    _wait_application_active(ctx, app_id)
    return app_id


def _safe_delete_application(ctx, app_id: str) -> None:
    try:
        ctx.client("opensearch").delete_application(id=app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_application_active(ctx, app_id: str, timeout_s: float = 300, interval_s: float = 1):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = _throttled(opensearch.get_application, id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"application {app_id} to become ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s")


def _wait_attachment_status(ctx, app_id: str, data_source_arn: str, timeout_s: float = 300, interval_s: float = 1):
    opensearch = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _throttled(opensearch.describe_data_source_attachment, id=app_id, dataSourceArn=data_source_arn)["status"]
        if status in ("ATTACHED", "FAILED"):
            return status
        time.sleep(interval_s)
    return status


def _outcome(fn, *args):
    """Run fn(*args) in a worker and return (error_code, message); raise if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn(*args)
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this StartMigration, but it SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
