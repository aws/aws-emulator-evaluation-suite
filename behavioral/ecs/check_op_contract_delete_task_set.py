"""op-contract-deleteTaskSet."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-deleteTaskSet"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTaskSet removes a non-primary task set but rejects deleting the PRIMARY one without force."""
    ecs = ctx.client("ecs")

    cluster_name = ctx.unique_name("sim2real-behav-cluster-")
    ecs.create_cluster(clusterName=cluster_name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    family = ctx.unique_name("sim2real-behav-td-")
    reg = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 128,
                "memory": 128,
                "essential": True,
            }
        ],
        tags=[{"key": "sim2real", "value": "true"}],
    )
    td_arn = reg["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, td_arn))

    service_name = ctx.unique_name("sim2real-behav-svc-")
    ecs.create_service(
        cluster=cluster_name,
        serviceName=service_name,
        deploymentController={"type": "EXTERNAL"},
        desiredCount=0,
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=cluster_name, service=service_name, force=True))

    ts1 = ecs.create_task_set(
        service=service_name,
        cluster=cluster_name,
        taskDefinition=td_arn,
        launchType="EC2",
        scale={"value": 0, "unit": "PERCENT"},
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskSet"]
    assert ts1["status"] == "ACTIVE", f"expected freshly created task set ACTIVE, got {ts1['status']}"

    del_resp = ecs.delete_task_set(cluster=cluster_name, service=service_name, taskSet=ts1["id"])
    assert del_resp["taskSet"]["id"] == ts1["id"], (
        f"expected DeleteTaskSet response to echo {ts1['id']}, got {del_resp['taskSet']['id']}"
    )

    # DescribeTaskSets requires an explicit, non-empty `taskSets` list on real AWS -- omitting
    # it (intending "list everything") trips server-side validation ("TaskSets cannot be
    # empty") once the service has zero task sets left, rather than returning an empty list.
    # Query the specific (just-deleted) ID instead: an empty `taskSets` result for that ID
    # still proves the deletion took effect, without relying on the unsupported "list all" form.
    # DeleteTaskSet's removal isn't synchronous on real AWS -- immediately afterward,
    # DescribeTaskSets can still momentarily echo the just-deleted id (e.g. while it drains),
    # so poll with a bound instead of asserting on the very next call.
    def _remaining_ids(ts_id):
        return [
            ts["id"]
            for ts in ecs.describe_task_sets(
                cluster=cluster_name, service=service_name, taskSets=[ts_id]
            )["taskSets"]
        ]

    remaining_ids = _poll_until(
        lambda: _remaining_ids(ts1["id"]), lambda ids: ts1["id"] not in ids, timeout_s=60.0, interval_s=3.0
    )
    assert ts1["id"] not in remaining_ids, f"expected {ts1['id']} gone after DeleteTaskSet, still in {remaining_ids}"

    ts2 = ecs.create_task_set(
        service=service_name,
        cluster=cluster_name,
        taskDefinition=td_arn,
        launchType="EC2",
        scale={"value": 0, "unit": "PERCENT"},
        tags=[{"key": "sim2real", "value": "true"}],
    )["taskSet"]
    ecs.update_service_primary_task_set(
        cluster=cluster_name, service=service_name, primaryTaskSet=ts2["taskSetArn"]
    )
    described_ts2 = ecs.describe_task_sets(
        cluster=cluster_name, service=service_name, taskSets=[ts2["taskSetArn"]]
    )["taskSets"][0]
    assert described_ts2["status"] == "PRIMARY", (
        f"expected ts2 PRIMARY after UpdateServicePrimaryTaskSet, got {described_ts2['status']}"
    )

    # Real AWS rejects this with InvalidParameterException (not ClientException) -- the
    # error message explains that the PRIMARY task set must be reassigned via
    # UpdateServicePrimaryTaskSet before it can be deleted.
    err, message = _error(
        lambda: ecs.delete_task_set(cluster=cluster_name, service=service_name, taskSet=ts2["id"])
    )
    assert err == "InvalidParameterException", f"expected InvalidParameterException (cannot delete PRIMARY), got {err}"
    expected_message = 'Primary TaskSet cannot be deleted'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_present = ecs.describe_task_sets(
        cluster=cluster_name, service=service_name, taskSets=[ts2["taskSetArn"]]
    )["taskSets"]
    assert len(still_present) == 1 and still_present[0]["status"] == "PRIMARY", (
        f"expected ts2 to remain the sole PRIMARY task set after the rejected delete, got {still_present}"
    )

    ecs.delete_task_set(cluster=cluster_name, service=service_name, taskSet=ts2["id"], force=True)

    # The force delete of the (former) PRIMARY task set is itself an unasserted delete --
    # prove it actually took effect via the same independent-read pattern used for ts1 above.
    remaining_ts2_ids = _poll_until(
        lambda: _remaining_ids(ts2["id"]), lambda ids: ts2["id"] not in ids, timeout_s=60.0, interval_s=3.0
    )
    assert ts2["id"] not in remaining_ts2_ids, (
        f"expected {ts2['id']} gone after forced DeleteTaskSet, still in {remaining_ts2_ids}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
