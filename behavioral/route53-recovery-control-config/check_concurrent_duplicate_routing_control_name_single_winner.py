"""concurrent-duplicate-routing-control-name-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-duplicate-routing-control-name-single-winner"
GROUP = "concurrency"
SERVICES = ["route53-recovery-control-config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:route53-arc-cluster")
def run(ctx) -> None:
    """Concurrent CreateRoutingControl calls with the same name in one control panel: exactly
    one succeeds and the rest fail with ValidationException (not the documented
    ConflictException), leaving exactly one routing control of that name."""
    client = ctx.client("route53-recovery-control-config")

    cluster_arn = _create_cluster_with_retry(
        client, ctx.unique_name("sim2real-r53arc-cluster-"), tags={"sim2real": "behavioral"}
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(ctx, client, cluster_arn))

    panel_arn = client.create_control_panel(
        ClusterArn=cluster_arn,
        ControlPanelName=ctx.unique_name("sim2real-r53arc-panel-"),
        Tags={"sim2real": "behavioral"},
    )["ControlPanel"]["ControlPanelArn"]
    ctx.on_cleanup(lambda: _safe_call(ctx, lambda: client.delete_control_panel(ControlPanelArn=panel_arn)))

    race_name = ctx.unique_name("sim2real-r53arc-race-")
    n_racers = 5

    def attempt(_i):
        try:
            arn = client.create_routing_control(
                ClusterArn=cluster_arn,
                ControlPanelArn=panel_arn,
                RoutingControlName=race_name,
            )["RoutingControl"]["RoutingControlArn"]
            return ("ok", arn)
        except Exception as err:  # noqa: BLE001
            from botocore.exceptions import ClientError

            if isinstance(err, ClientError):
                return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message", ""))
            raise

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(attempt, i) for i in range(n_racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, results
    assert len(failures) == n_racers - 1, results
    # The message carries a server-chosen id before the name, so only its fixed prefix and the
    # name it ends with are asserted.
    prefix = "A routing control with the specified name already exists: "
    for _, code, message in failures:
        assert code == "ValidationException", failures
        assert message.startswith(prefix), f"expected message starting {prefix!r}, got {message!r}"
        assert message.endswith(f", {race_name}"), f"expected message ending ', {race_name}', got {message!r}"

    winner_arn = successes[0][1]
    ctx.on_cleanup(
        lambda: _safe_call(ctx, lambda: client.delete_routing_control(RoutingControlArn=winner_arn))
    )

    listed = client.list_routing_controls(ControlPanelArn=panel_arn)["RoutingControls"]
    matches = [rc for rc in listed if rc["Name"] == race_name]
    assert len(matches) == 1, listed
    assert matches[0]["RoutingControlArn"] == winner_arn, (winner_arn, matches[0])


# ===== helpers =====
def _create_cluster_with_retry(client, name, tags=None, timeout_s=60.0, interval_s=10.0):
    """CreateCluster, retrying ServiceQuotaExceededException for a bounded window —
    the account's 2-cluster quota may still be draining an async delete from a
    prior check's teardown."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return client.create_cluster(ClusterName=name, Tags=tags or {})["Cluster"]["ClusterArn"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


# The suite's cleanup budget; one deadline is shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN_DEADLINES: dict = {}


def _teardown_deadline(ctx) -> float:
    """The run's one teardown deadline, a margin inside the budget so a teardown raises its own
    error before the runner gives up; keyed by the run's ctx, so no run inherits another's."""
    held = _TEARDOWN_DEADLINES.get(id(ctx))
    if held is None or held[0] is not ctx:
        held = _TEARDOWN_DEADLINES[id(ctx)] = (ctx, time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    return held[1]


def _in_progress(error) -> bool:
    """The ValidationException refusals of a teardown that is only early: a routing control not
    yet DEPLOYED, a control panel whose routing controls are still being deleted."""
    message = error.get("Message", "")
    return error["Code"] == "ValidationException" and (
        message.startswith("Expected [DEPLOYED] but found ")
        or message == "Cannot delete non-empty control panel"
    )


def _safe_call(ctx, fn) -> None:
    """Teardown delete: done on success or ResourceNotFoundException; retry the in-progress
    refusals every 2 s to the shared deadline, and raise everything else."""
    deadline = _teardown_deadline(ctx)
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if not _in_progress(exc.response["Error"]) or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_cluster_and_wait(ctx, client, cluster_arn, interval_s=2.0) -> None:
    """Delete a cluster and block until it's actually gone — the account's cluster
    quota (2) is only freed once deletion truly completes, not when DeleteCluster
    returns, so the NEXT check that needs a fresh cluster must wait for this one."""
    deadline = _teardown_deadline(ctx)
    while True:
        try:
            client.delete_cluster(ClusterArn=cluster_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # refused while the cluster's control panels are still being deleted
            if code not in ("ConflictException", "ValidationException") or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            client.describe_cluster(ClusterArn=cluster_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"cluster {cluster_arn} was not deleted by the cleanup deadline")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
