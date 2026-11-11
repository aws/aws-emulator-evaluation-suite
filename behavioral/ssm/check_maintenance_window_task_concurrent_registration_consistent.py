"""maintenance-window-task-concurrent-registration-consistent."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "maintenance-window-task-concurrent-registration-consistent"
GROUP = "concurrency"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent RegisterTaskWithMaintenanceWindow calls on one window each return a distinct
    WindowTaskId, and DescribeMaintenanceWindowTasks lists exactly those tasks: none lost or
    duplicated."""
    ssm = ctx.client("ssm")

    doc_name = ctx.unique_name("Sim2RealMWNoOp")
    content = json.dumps(
        {
            "schemaVersion": "0.3",
            "description": "sim2real no-op automation for maintenance window task registration",
            "mainSteps": [
                {"name": "sleep", "action": "aws:sleep", "inputs": {"Duration": "PT1S"}}
            ],
        }
    )
    ssm.create_document(
        Content=content,
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))

    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule="cron(0 10 * * ? *)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    task_count = 6

    def _register(i: int) -> str:
        return ssm.register_task_with_maintenance_window(
            WindowId=window_id,
            TaskArn=doc_name,
            TaskType="AUTOMATION",
            Priority=1,
            Name=ctx.unique_name(f"sim2real-mwtask{i}-"),
        )["WindowTaskId"]

    with ThreadPoolExecutor(max_workers=task_count) as pool:
        task_ids = list(pool.map(_register, range(task_count)))

    def _deregister_all():
        for task_id in task_ids:
            ssm.deregister_task_from_maintenance_window(WindowId=window_id, WindowTaskId=task_id)

    ctx.on_cleanup(_deregister_all)

    assert len(task_ids) == task_count, (
        f"expected {task_count} WindowTaskIds from {task_count} concurrent registrations, got "
        f"{len(task_ids)}"
    )
    assert len(set(task_ids)) == task_count, (
        f"concurrent registration handed out a duplicate WindowTaskId: {task_ids}"
    )

    listed_ids = _list_all_task_ids(ssm, window_id)
    assert listed_ids == set(task_ids), (
        f"registered {sorted(set(task_ids))} but DescribeMaintenanceWindowTasks lists "
        f"{sorted(listed_ids)} -- a concurrent registration was lost or a phantom appeared"
    )


def _list_all_task_ids(ssm, window_id: str) -> set:
    listed_ids: set = set()
    next_token = None
    while True:
        kwargs = {"WindowId": window_id}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = ssm.describe_maintenance_window_tasks(**kwargs)
        for task in resp.get("Tasks", []):
            listed_ids.add(task["WindowTaskId"])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return listed_ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
