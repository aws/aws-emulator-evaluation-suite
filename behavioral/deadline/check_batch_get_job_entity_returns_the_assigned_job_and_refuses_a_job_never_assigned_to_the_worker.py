"""batch-get-job-entity-returns-the-assigned-job-and-refuses-a-job-never-assigned-to-the-worker."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-job-entity-returns-the-assigned-job-and-refuses-a-job-never-assigned-to-the-worker"
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A worker reads the job and step details of the job it was assigned through BatchGetJobEntity,
    and in the same batch is refused the details of a job it was never assigned."""
    dl = ctx.client("deadline")
    farm_id, farm_arn = _farm(ctx, dl)
    fleet_id = _fleet(ctx, dl, farm_id, farm_arn)
    served = _queue(ctx, dl, farm_id)
    _associate(ctx, dl, farm_id, served, fleet_id)
    unserved = _queue(ctx, dl, farm_id)
    worker_id = _started_worker(ctx, dl, farm_id, fleet_id)
    idle = _schedule(dl, farm_id, fleet_id, worker_id)
    assert idle["assignedSessions"] == {}, f"a farm with no job assigns nothing, got {idle['assignedSessions']!r}"

    assigned = _job(dl, farm_id, served)
    assert assigned["taskRunStatus"] == "READY", f"the served queue's job is {assigned['taskRunStatus']!r}, not READY"
    stranger = _job(dl, farm_id, unserved, served=False)
    job_id, other_id = assigned["jobId"], stranger["jobId"]
    steps = _all(lambda **kw: dl.list_steps(farmId=farm_id, queueId=served, jobId=job_id, **kw), "steps")
    assert [s["name"] for s in steps] == [_STEP], f"expected the one step {_STEP!r}, got {steps!r}"
    step_id = steps[0]["stepId"]

    schedule = _wait(
        lambda: _schedule(dl, farm_id, fleet_id, worker_id),
        lambda s: bool(s["assignedSessions"]), "a session assigned to the worker", cap_s=120, every_s=5,
    )
    sessions = list(schedule["assignedSessions"].values())
    assert [s["jobId"] for s in sessions] == [job_id], f"expected one session for the served job, got {sessions!r}"
    ctx.on_cleanup(_finish(dl, farm_id, fleet_id, worker_id, sessions[0]["sessionActions"]))

    batch = dl.batch_get_job_entity(farmId=farm_id, fleetId=fleet_id, workerId=worker_id, identifiers=[
        {"jobDetails": {"jobId": job_id}},
        {"stepDetails": {"jobId": job_id, "stepId": step_id}},
        {"jobDetails": {"jobId": other_id}},
    ])
    jobs = [e["jobDetails"] for e in batch["entities"] if "jobDetails" in e]
    assert [j["jobId"] for j in jobs] == [job_id], (
        f"only the assigned job's details come back, got jobs {[j['jobId'] == job_id for j in jobs]!r} (True = assigned)"
    )
    details = jobs[0]
    assert details["logGroupName"] == f"/aws/deadline/{farm_id}/{served}", (
        f"the job logs to its queue's log group, got {details['logGroupName']!r}"
    )
    assert details["schemaVersion"] == "jobtemplate-2023-09", f"unexpected schemaVersion {details['schemaVersion']!r}"
    assert details.get("jobRunAsUser") == {"runAs": "WORKER_AGENT_USER"}, (
        f"the job runs as its queue's user, got {details.get('jobRunAsUser')!r}"
    )
    step = [e["stepDetails"] for e in batch["entities"] if "stepDetails" in e]
    assert [(d["jobId"], d["stepId"]) for d in step] == [(job_id, step_id)], f"expected the assigned step, got {step!r}"
    assert step[0]["template"] == {"name": _STEP, "script": {"actions": {"onRun": {"command": "echo", "args": ["frame"]}}}}, (
        f"the step template must be the submitted step, got {step[0]['template']!r}"
    )
    assert step[0]["dependencies"] == [], f"a lone step depends on nothing, got {step[0]['dependencies']!r}"
    assert len(batch["entities"]) == 2, f"expected two entities, got {len(batch['entities'])}"

    errors = batch["errors"]
    assert len(errors) == 1 and list(errors[0]) == ["jobDetails"], f"expected one jobDetails error, got {errors!r}"
    refused = errors[0]["jobDetails"]
    assert refused["jobId"] == other_id, "the error must name the job never assigned to the worker"
    assert refused["code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {refused['code']!r}"
    assert refused["message"] == f"Resource of type job with id {other_id} does not exist.", (
        f"unexpected message {refused['message']!r}"
    )


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


def _finish(dl, farm_id: str, fleet_id: str, worker_id: str, actions: list):
    """A cleanup reporting the worker's assigned actions SUCCEEDED, so its session ends before it stops."""

    def report() -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        _schedule(dl, farm_id, fleet_id, worker_id, updatedSessionActions={
            a["sessionActionId"]: {"completedStatus": "SUCCEEDED", "processExitCode": 0, "startedAt": now,
                                   "endedAt": now, "progressPercent": 100.0}
            for a in actions
        })

    return report


# ===== the farm, its fleet and queues, and the worker =====


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


def _farm(ctx, dl) -> tuple[str, str]:
    """A farm and its ARN; its cleanup runs after everything created in it is gone."""
    farm_id = dl.create_farm(displayName=ctx.unique_name("sim2real-farm-"), tags=_TAGS)["farmId"]
    ctx.on_cleanup(_teardown(lambda: _retrying(lambda: dl.delete_farm(farmId=farm_id), busy=("ConflictException",)),
                             "ResourceNotFoundException"))
    ctx.on_cleanup(_reap_farm_logs(ctx, farm_id))
    farm_arn = dl.get_farm(farmId=farm_id).get("farmArn") or (
        f"arn:aws:deadline:{ctx.region}:{ctx.account}:farm/{farm_id}")
    return farm_id, farm_arn


def _queue(ctx, dl, farm_id: str, **extra) -> str:
    """A queue of the farm whose jobs run as the worker agent's user; a role is retried until IAM has it."""
    queue_id = _retrying(lambda: dl.create_queue(
        farmId=farm_id, displayName=ctx.unique_name("sim2real-queue-"),
        jobRunAsUser={"runAs": "WORKER_AGENT_USER"}, tags=_TAGS, **extra,
    ), busy=("ValidationException", "AccessDeniedException"))["queueId"]

    def drop_queue():
        _retrying(lambda: dl.delete_queue(farmId=farm_id, queueId=queue_id), busy=("ConflictException",))
        _wait(lambda: _gone(lambda: dl.get_queue(farmId=farm_id, queueId=queue_id)), bool,
              f"queue {queue_id} deleted", cap_s=120)

    ctx.on_cleanup(_teardown(drop_queue, "ResourceNotFoundException"))
    return queue_id


def _fleet(ctx, dl, farm_id: str, farm_arn: str) -> str:
    """An ACTIVE customer-managed fleet of the farm, for one Linux x86_64 worker."""
    role_arn = _fleet_role(ctx, farm_arn)
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
    return fleet_id


def _associate(ctx, dl, farm_id: str, queue_id: str, fleet_id: str) -> None:
    """The fleet serves the queue; the cleanup stops the association, waits for STOPPED and deletes it."""
    dl.create_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)

    def drop_association():
        dl.update_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id,
                                          status="STOP_SCHEDULING_AND_CANCEL_TASKS")
        _wait(lambda: dl.get_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id),
              lambda a: a["status"] == "STOPPED", "association stopped", cap_s=120, every_s=5)
        dl.delete_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)

    ctx.on_cleanup(_teardown(drop_association, "ResourceNotFoundException"))


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
