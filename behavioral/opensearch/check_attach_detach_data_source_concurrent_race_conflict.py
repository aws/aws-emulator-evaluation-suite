"""attach-detach-data-source-concurrent-race-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "attach-detach-data-source-concurrent-race-conflict"
GROUP = "concurrency"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While an attachment is still PENDING, a concurrent repeat AttachDataSource succeeds and a concurrent
    DetachDataSource fails with ConflictException and its exact message; the attachment then settles to
    ATTACHED and a later detach succeeds.
    """
    osx = ctx.client("opensearch")

    # The application settles first, so the domain created right after it is still provisioning
    # when the attachment below starts: AttachDataSource completes immediately only when BOTH the
    # application and the domain are already active.
    app_id = osx.create_application(
        name=_app_name(ctx),
        tagList=[{"Key": "sim2real", "Value": "attach-detach-data-source-concurrent-race-conflict"}],
    )["id"]
    ctx.on_cleanup(lambda: osx.delete_application(id=app_id))
    _wait_application_active(ctx, app_id, timeout_s=180)

    domain_name = _domain_name(ctx)
    osx.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.11",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": "attach-detach-data-source-concurrent-race-conflict"}],
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_name))
    domain_arn = _domain_arn(ctx, domain_name)

    # initiate the attachment -- since the domain is still provisioning, this
    # lands in status PENDING. This call is not itself part of the race: it
    # creates the in-flight window that the concurrent calls below land in.
    # The check holds that window itself: _assert_domain_still_creating brackets
    # the PENDING read and the race, so both are graded while the domain is
    # verifiably still being created, never on an assumed creation duration.
    _assert_domain_still_creating(osx, domain_name)
    started = osx.attach_data_source(id=app_id, dataSourceArn=domain_arn)
    assert started["status"] == "PENDING", (
        f"expected the fresh attachment against a still-creating domain to be "
        f"PENDING, got {started['status']!r}"
    )

    barrier = threading.Barrier(2)

    def call_attach():
        barrier.wait(timeout=10)
        return _try_call(lambda: osx.attach_data_source(id=app_id, dataSourceArn=domain_arn))

    def call_detach():
        barrier.wait(timeout=10)
        return _try_call(lambda: osx.detach_data_source(id=app_id, dataSourceArn=domain_arn))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_attach = pool.submit(call_attach)
        fut_detach = pool.submit(call_detach)
        r_attach = fut_attach.result()
        r_detach = fut_detach.result()

    results = [("attach", r_attach), ("detach", r_detach)]
    _assert_domain_still_creating(osx, domain_name)

    # the redundant attach must not fail: it is idempotent against the
    # in-flight (PENDING) attachment it raced against.
    assert r_attach[0] == "ok", f"expected concurrent redundant attach to succeed, got {results}"
    # the detach must be rejected: it raced against a PENDING attachment on
    # the same data source and lost.
    assert r_detach[0] == "err", f"expected concurrent detach to be rejected, got {results}"
    assert r_detach[1] == "ConflictException", f"unexpected loser error code: {results}"
    expected_message = (
        f"Data source {domain_arn} attachment to application {app_id} is still PENDING."
    )
    assert r_detach[2] == expected_message, (
        f"loser DetachDataSource reports {r_detach[2]!r}, expected {expected_message!r}"
    )

    # the attachment must eventually settle to ATTACHED once the domain
    # finishes provisioning -- never left half-attached by the losing detach.
    final = _wait_attachment_status(ctx, app_id, domain_arn, {"ATTACHED"}, timeout_s=1800)
    assert final["status"] == "ATTACHED", (
        f"expected the attachment to settle to ATTACHED once the domain finished "
        f"provisioning (never left half-attached by the losing detach), got {final!r}"
    )

    # positive control: a solo detach (once settled) still cleanly succeeds
    solo = _try_call(lambda: osx.detach_data_source(id=app_id, dataSourceArn=domain_arn))
    assert solo[0] == "ok", f"expected solo positive-control detach to succeed, got {solo}"


def _app_name(ctx) -> str:
    return ctx.unique_name("sim2r-osaapp-")[:30].lower().rstrip("-")


def _domain_name(ctx) -> str:
    return ctx.unique_name("sim2r-osadom-")[:28].lower().rstrip("-")


def _try_call(fn):
    from botocore.exceptions import ClientError

    try:
        return ("ok", fn())
    except ClientError as exc:
        return ("err", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))


def _assert_domain_still_creating(osx, domain_name) -> None:
    status = osx.describe_domain(DomainName=domain_name)["DomainStatus"]
    assert status.get("Processing") is True and status.get("Endpoint") is None, (
        f"domain {domain_name} left its creating window while the check held it: "
        f"Processing={status.get('Processing')!r}, Endpoint={status.get('Endpoint')!r}"
    )


def _domain_arn(ctx, domain_name):
    osx = ctx.client("opensearch")
    return osx.describe_domain(DomainName=domain_name)["DomainStatus"]["ARN"]



def _delete_domain(ctx, domain_name):
    from botocore.exceptions import ClientError

    osx = ctx.client("opensearch")
    try:
        osx.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_application_active(ctx, app_id, timeout_s=180, interval_s=2):
    osx = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        app = osx.get_application(id=app_id)
        last_status = app["status"]
        if last_status == "ACTIVE":
            return app
        if last_status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED status")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"application {app_id} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"application {app_id} did not become ACTIVE within {timeout_s}s (last: {last_status})")


def _wait_attachment_status(ctx, app_id, data_source_arn, target_statuses, timeout_s=120, interval_s=2):
    osx = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        attachment = osx.describe_data_source_attachment(id=app_id, dataSourceArn=data_source_arn)
        last_status = attachment["status"]
        if last_status in target_statuses:
            return attachment
        if last_status == "FAILED":
            raise AssertionError(f"attachment for {data_source_arn} entered FAILED status")
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"attachment reaching {target_statuses}: the run budget ended first; not graded")
    raise AssertionError(
        f"attachment for {data_source_arn} did not reach {target_statuses} within {timeout_s}s "
        f"(last: {last_status})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
