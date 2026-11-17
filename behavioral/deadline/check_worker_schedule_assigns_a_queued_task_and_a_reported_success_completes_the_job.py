"""worker-schedule-assigns-a-queued-task-and-a-reported-success-completes-the-job."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "worker-schedule-assigns-a-queued-task-and-a-reported-success-completes-the-job"
GROUP = "worker-data-plane"
SERVICES = ["deadline"]

_TAGS = {"sim2real": CHECK}
_FLEET_POLICY = "arn:aws:iam::aws:policy/AWSDeadlineCloud-FleetWorker"
_STEP = "render"
_CAPABILITIES = {
    "amounts": [{"name": "amount.worker.vcpu", "value": 2.0}, {"name": "amount.worker.memory", "value": 4096.0}],
    "attributes": [{"name": "attr.worker.os.family", "values": ["linux"]},
                   {"name": "attr.worker.cpu.arch", "values": ["x86_64"]}],
}


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A started worker on a fleet serving a queue is handed a session whose one action runs the
    job's only task; reporting that action SUCCEEDED marks the task and the job SUCCEEDED."""
    dl = ctx.client("deadline")
    farm_id, fleet_id, queue_id = _farm_fleet_queue(ctx, dl)

    worker_id = _started_worker(ctx, dl, farm_id, fleet_id)
    # A worker's first schedule is answered once the farm has settled the new fleet and association.
    idle = _schedule(dl, farm_id, fleet_id, worker_id)
    assert idle["assignedSessions"] == {}, f"a farm with no job assigns nothing, got {idle['assignedSessions']!r}"

    job = _job(dl, farm_id, queue_id)
    job_id = job["jobId"]
    assert job["taskRunStatus"] == "READY", (
        f"a job without host requirements on a queue a fleet serves is READY, got {job['taskRunStatus']!r}"
    )
    steps = _all(lambda **kw: dl.list_steps(farmId=farm_id, queueId=queue_id, jobId=job_id, **kw), "steps")
    assert [s["name"] for s in steps] == [_STEP], f"expected the one step {_STEP!r}, got {steps!r}"
    step_id = steps[0]["stepId"]
    tasks = _all(lambda **kw: dl.list_tasks(
        farmId=farm_id, queueId=queue_id, jobId=job_id, stepId=step_id, **kw), "tasks")
    assert len(tasks) == 1, f"a step without parameters has exactly one task, got {tasks!r}"
    task_id = tasks[0]["taskId"]

    schedule = _wait(
        lambda: _schedule(dl, farm_id, fleet_id, worker_id),
        lambda s: bool(s["assignedSessions"]), "a session assigned to the worker", cap_s=120, every_s=5,
    )
    assert len(schedule["assignedSessions"]) == 1, (
        f"one job with one task yields one session, got {schedule['assignedSessions']!r}"
    )
    session_id, session = next(iter(schedule["assignedSessions"].items()))
    assert (session["jobId"], session["queueId"]) == (job_id, queue_id), (
        f"the session must belong to the queued job, got job {session['jobId']!r} queue {session['queueId']!r}"
    )
    actions = session["sessionActions"]
    runs = [a for a in actions if "taskRun" in a["definition"]]
    assert len(runs) == 1, f"expected exactly one taskRun action, got {actions!r}"
    run_def = runs[0]["definition"]["taskRun"]
    assert (run_def["stepId"], run_def["taskId"]) == (step_id, task_id), (
        f"the taskRun action must name the job's only step and task, got {run_def!r}"
    )
    assert schedule["updateIntervalSeconds"] >= 0, f"updateIntervalSeconds is {schedule!r}"

    started = datetime.datetime.now(datetime.timezone.utc)
    report = {
        a["sessionActionId"]: {
            "completedStatus": "SUCCEEDED",
            "processExitCode": 0,
            "startedAt": started,
            "endedAt": started + datetime.timedelta(seconds=1),
            "progressPercent": 100.0,
        }
        for a in actions
    }
    _schedule(dl, farm_id, fleet_id, worker_id, updatedSessionActions=report)

    run_action = _wait(
        lambda: dl.get_session_action(farmId=farm_id, queueId=queue_id, jobId=job_id,
                                      sessionActionId=runs[0]["sessionActionId"]),
        lambda a: a["status"] == "SUCCEEDED", "the taskRun action SUCCEEDED", cap_s=60,
    )
    assert run_action.get("processExitCode") == 0, f"the reported exit code was not kept: {run_action!r}"
    assert run_action["sessionId"] == session_id, f"the action moved sessions: {run_action!r}"
    task = _wait(lambda: dl.get_task(farmId=farm_id, queueId=queue_id, jobId=job_id, stepId=step_id, taskId=task_id),
                 lambda t: t["runStatus"] == "SUCCEEDED", "the task SUCCEEDED", cap_s=60)
    assert task.get("failureRetryCount", 0) == 0, f"a first-run success retries nothing: {task!r}"
    job = _wait(lambda: dl.get_job(farmId=farm_id, queueId=queue_id, jobId=job_id),
                lambda j: j["taskRunStatus"] == "SUCCEEDED", "the job SUCCEEDED", cap_s=60)
    counts = {k: v for k, v in job.get("taskRunStatusCounts", {}).items() if v}
    assert counts == {"SUCCEEDED": 1}, f"expected one SUCCEEDED task and nothing else, got {counts!r}"


# ===== the farm, its fleet and queue, and the worker =====


def _teardown(undo, *gone: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in gone:
                raise

    return run_undo


def _retrying(call, *, busy: tuple[str, ...], gone: tuple[str, ...] = (), attempts: int = 10):
    """``call()`` retried with backoff while it answers one of ``busy``; ``gone`` ends it quietly."""
    delay = 2.0
    for attempt in range(attempts):
        try:
            return call()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return None
            if code not in busy or attempt == attempts - 1:
                raise
        time.sleep(delay)
        delay = min(delay * 1.6, 20.0)
    return None


def _wait(probe, done, what: str, *, cap_s: float, every_s: float = 3.0):
    """Poll ``probe`` until ``done`` holds, else fail naming the last observation."""
    end = time.monotonic() + cap_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= end:
            raise AssertionError(f"{what}: not reached within {cap_s:.0f}s; last observed {last!r}")
        time.sleep(every_s)


def _all(page, key: str) -> list:
    out, token = [], None
    while True:
        resp = page(**({"nextToken": token} if token else {}))
        out += resp[key]
        token = resp.get("nextToken")
        if not token:
            return out


def _gone(probe) -> bool:
    try:
        probe()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _schedule(dl, farm_id: str, fleet_id: str, worker_id: str, **report) -> dict:
    """One UpdateWorkerSchedule call; the service answers ConflictException while it settles the farm."""
    return _retrying(lambda: dl.update_worker_schedule(farmId=farm_id, fleetId=fleet_id, workerId=worker_id, **report),
                     busy=("ConflictException",))


def _reap_farm_logs(ctx, farm_id: str):
    """A cleanup deleting the log groups Deadline Cloud made for the farm's queue and fleet."""
    logs = ctx.client("logs")
    prefix = f"/aws/deadline/{farm_id}/"

    def reap() -> None:
        clean = 0
        for _ in range(20):
            names = [g["logGroupName"] for p in logs.get_paginator("describe_log_groups").paginate(
                logGroupNamePrefix=prefix) for g in p["logGroups"]]
            clean = 0 if names else clean + 1
            if clean >= 2:
                return
            for name in names:
                _teardown(lambda n=name: logs.delete_log_group(logGroupName=n), "ResourceNotFoundException")()
            time.sleep(3)
        raise AssertionError(f"log groups under {prefix} kept reappearing: {names!r}")

    return reap


def _job(dl, farm_id: str, queue_id: str, *, served: bool = True) -> dict:
    """A one-task job on the queue, once Deadline Cloud has evaluated it against the queue's fleets.

    A job evaluated before a new association reaches the scheduler is NOT_COMPATIBLE and stays so
    until requeued, so a served queue's job is requeued, a bounded number of times, until READY.
    """
    job_id = dl.create_job(farmId=farm_id, queueId=queue_id, template=_job_template(), templateType="JSON",
                           priority=50)["jobId"]

    def get():
        return dl.get_job(farmId=farm_id, queueId=queue_id, jobId=job_id)

    job = _wait(get, lambda j: j["lifecycleStatus"] != "CREATE_IN_PROGRESS" and j["taskRunStatus"] != "PENDING",
                "job created and evaluated", cap_s=120)
    requeues = 0
    while served and job["taskRunStatus"] == "NOT_COMPATIBLE" and requeues < 6:
        requeues += 1
        dl.update_job(farmId=farm_id, queueId=queue_id, jobId=job_id, targetTaskRunStatus="READY")
        for _ in range(15):
            time.sleep(2)
            job = get()
            if job["taskRunStatus"] == "READY":
                break
    return job


def _job_template() -> str:
    return json.dumps({
        "specificationVersion": "jobtemplate-2023-09",
        "name": "sim2real-one-task",
        "steps": [{"name": _STEP, "script": {"actions": {"onRun": {"command": "echo", "args": ["frame"]}}}}],
    })


def _fleet_role(ctx, farm_arn: str) -> str:
    """A fleet role Deadline Cloud's credentials service assumes for this farm only."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-dl-fleet-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "credentials.deadline.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account},
                          "ArnEquals": {"aws:SourceArn": farm_arn}},
        }],
    }
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                          Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=name, PolicyArn=_FLEET_POLICY)
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_FLEET_POLICY), "NoSuchEntity"))
    return arn


def _farm_fleet_queue(ctx, dl) -> tuple[str, str, str]:
    """A farm with one customer-managed fleet serving one queue through an ACTIVE association."""
    farm = dl.create_farm(displayName=ctx.unique_name("sim2real-farm-"), tags=_TAGS)
    farm_id = farm["farmId"]
    ctx.on_cleanup(_teardown(lambda: _retrying(lambda: dl.delete_farm(farmId=farm_id), busy=("ConflictException",)),
                             "ResourceNotFoundException"))
    ctx.on_cleanup(_reap_farm_logs(ctx, farm_id))
    farm_arn = dl.get_farm(farmId=farm_id).get("farmArn") or (
        f"arn:aws:deadline:{ctx.region}:{ctx.account}:farm/{farm_id}")
    role_arn = _fleet_role(ctx, farm_arn)

    queue_id = dl.create_queue(farmId=farm_id, displayName=ctx.unique_name("sim2real-queue-"),
                               jobRunAsUser={"runAs": "WORKER_AGENT_USER"}, tags=_TAGS)["queueId"]

    def drop_queue():
        _retrying(lambda: dl.delete_queue(farmId=farm_id, queueId=queue_id), busy=("ConflictException",))
        _wait(lambda: _gone(lambda: dl.get_queue(farmId=farm_id, queueId=queue_id)), bool,
              f"queue {queue_id} deleted", cap_s=120)

    ctx.on_cleanup(_teardown(drop_queue, "ResourceNotFoundException"))

    # The role is assumable only once IAM has propagated it; CreateFleet says so with a ValidationException.
    fleet_id = _retrying(lambda: dl.create_fleet(
        farmId=farm_id, displayName=ctx.unique_name("sim2real-fleet-"), roleArn=role_arn, maxWorkerCount=1,
        configuration={"customerManaged": {"mode": "NO_SCALING", "workerCapabilities": {
            "vCpuCount": {"min": 1, "max": 4}, "memoryMiB": {"min": 1024, "max": 8192},
            "osFamily": "LINUX", "cpuArchitectureType": "x86_64"}}},
        tags=_TAGS,
    ), busy=("ValidationException", "AccessDeniedException"))["fleetId"]

    def drop_fleet():
        _retrying(lambda: dl.delete_fleet(farmId=farm_id, fleetId=fleet_id), busy=("ConflictException",))
        _wait(lambda: _gone(lambda: dl.get_fleet(farmId=farm_id, fleetId=fleet_id)), bool,
              f"fleet {fleet_id} deleted", cap_s=180, every_s=5)

    ctx.on_cleanup(_teardown(drop_fleet, "ResourceNotFoundException"))
    fleet = _wait(lambda: dl.get_fleet(farmId=farm_id, fleetId=fleet_id),
                  lambda f: f["status"] != "CREATE_IN_PROGRESS", "fleet created", cap_s=120)
    assert fleet["status"] == "ACTIVE", f"the fleet did not become ACTIVE: {fleet['status']!r}"

    dl.create_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)

    def drop_association():
        dl.update_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id,
                                          status="STOP_SCHEDULING_AND_CANCEL_TASKS")
        _wait(lambda: dl.get_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id),
              lambda a: a["status"] == "STOPPED", "association stopped", cap_s=120, every_s=5)
        dl.delete_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)

    ctx.on_cleanup(_teardown(drop_association, "ResourceNotFoundException"))
    return farm_id, fleet_id, queue_id


def _started_worker(ctx, dl, farm_id: str, fleet_id: str) -> str:
    """A worker of the fleet, STARTED with capabilities inside the fleet's range."""
    worker_id = dl.create_worker(farmId=farm_id, fleetId=fleet_id, tags=_TAGS)["workerId"]

    def drop_worker():
        _retrying(lambda: dl.update_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id, status="STOPPED",
                                           capabilities=_CAPABILITIES),
                  busy=("ConflictException",), gone=("ResourceNotFoundException",))
        _retrying(lambda: dl.delete_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id),
                  busy=("ConflictException",))

    ctx.on_cleanup(_teardown(drop_worker, "ResourceNotFoundException"))
    dl.update_worker(
        farmId=farm_id, fleetId=fleet_id, workerId=worker_id, status="STARTED",
        capabilities=_CAPABILITIES,
    )
    return worker_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
