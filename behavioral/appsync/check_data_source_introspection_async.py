"""data-source-introspection-async."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")

def _poll_until(probe, predicate, *, timeout_s=90, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "data-source-introspection-async"
GROUP = 'data-source'
SERVICES = ['appsync']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Introspecting a nonexistent RDS Data API target starts PROCESSING, then polls to FAILED
    with a status detail; GetDataSourceIntrospection for a fabricated id fails NotFoundException.
    """
    svc = ctx.client("appsync")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resource_arn = f"arn:aws:rds:{ctx.region}:{account_id}:cluster:{ctx.unique_name('sim2real-behav-nonexistent-cluster-')}"
    secret_arn = f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:{ctx.unique_name('sim2real-behav-nonexistent-secret-')}"

    start_resp = svc.start_data_source_introspection(
        rdsDataApiConfig={
            "resourceArn": resource_arn,
            "secretArn": secret_arn,
            "databaseName": "sim2real_behav_db",
        }
    )
    introspection_id = start_resp["introspectionId"]
    assert start_resp.get("introspectionStatus") == "PROCESSING", (
        "expected a freshly started introspection job to begin PROCESSING (it cannot resolve to a "
        f"terminal state before its first poll), got {start_resp.get('introspectionStatus')!r}"
    )

    final = _poll_until(
        lambda: svc.get_data_source_introspection(introspectionId=introspection_id),
        lambda r: r["introspectionStatus"] in ("SUCCESS", "FAILED"),
        timeout_s=90,
        interval_s=3.0,
        description="data source introspection to reach a terminal state",
    )
    assert final["introspectionId"] == introspection_id, (
        f"GetDataSourceIntrospection returned a different introspectionId: {final['introspectionId']!r} "
        f"!= {introspection_id!r}"
    )
    assert final["introspectionStatus"] == "FAILED", (
        f"expected introspection of an unreachable RDS target to fail, got {final['introspectionStatus']!r}"
    )
    assert final.get("introspectionStatusDetail"), "a FAILED introspection must report a non-empty status detail"

    fake_introspection_id = ctx.unique_name("sim2real_behav_bogus_").replace("-", "_")
    code, code_msg = _error(
        lambda: svc.get_data_source_introspection(introspectionId=fake_introspection_id)
    )
    assert code == "NotFoundException", (
        f"expected NotFoundException for a nonexistent introspectionId, got {code}"
    )
    assert code_msg == "No introspection was found that matches the supplied ID.", f"unexpected message: {code_msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
