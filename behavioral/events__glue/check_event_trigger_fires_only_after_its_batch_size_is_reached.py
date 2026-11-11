"""event-trigger-fires-only-after-its-batch-size-is-reached."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-trigger-fires-only-after-its-batch-size-is-reached"
GROUP = 'eventing'
SERVICES = ['events', 'glue']

#: The batch size under test, and the window that must NOT be what fires the batch.
_BATCH_SIZE = 3
_BATCH_WINDOW_S = 900

#: The least the BatchSize=3 workflow is held at zero runs between the second and third delivery;
#: above it the hold is 5x the latency the BatchSize=1 twin measured on the same wiring, so the
#: third delivery's own latency may vary from the twin's and still sit under a third of the hold.
#: The floor is three of the 5 s run polls, the resolution either latency is measured at.
_ABSENCE_FLOOR_S = 30.0

#: Poll budget for a workflow run to appear after a delivery that should produce one.
_RUN_APPEARS_BUDGET_S = 480.0

#: Bound on the PutTargets retry and the warm-up delivery that wait out IAM role propagation.
_ROLE_PROPAGATION_TIMEOUT_S = 120.0
_WARM_DETAIL_TYPE = "sim2real.GlueEventTriggerWarmUp"

_GLUE_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"

#: The two AWS-managed policies the EventBridge console attaches by default to a role it will use
#: to invoke a target, alongside the inline per-target grant (here, glue:notifyEvent). Doc:
#: https://docs.aws.amazon.com/glue/latest/dg/starting-workflow-eventbridge.html step 2 ("The
#: wizard automatically attaches the CloudWatchEventsBuiltInTargetExecutionAccess and
#: CloudWatchEventsInvocationAccess policies").
_EVENTS_TARGET_POLICIES = (
    "arn:aws:iam::aws:policy/service-role/CloudWatchEventsBuiltInTargetExecutionAccess",
    "arn:aws:iam::aws:policy/service-role/CloudWatchEventsInvocationAccess",
)
_SOURCE = "sim2real.glue-event-batching"
_DETAIL_TYPE = "sim2real.GlueEventTrigger"

#: Deliberately non-existent: the observable is the workflow run, not the job's outcome, and a
#: failing action does not suppress the run record.
_ABSENT_SCRIPT_BUCKET_HINT = "sim2real-behav-glue-batching-script"


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    """Bounded retry that RAISES on timeout. Never a bare sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _role(ctx, iam, name: str, service: str, inline: dict, managed: tuple = ()) -> str:
    """A role trusting *service*, with one inline policy plus zero or more AWS-managed policies
    attached. Created here, never adopted."""
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": service},
                "Action": "sts:AssumeRole",
            }],
        }),
        Description="sim2real-behav glue event batching",
        Tags=[{"Key": "sim2real", "Value": "glue-event-batching"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _drop_role(iam, name, managed))
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps(inline))
    for policy_arn in managed:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    return arn


def _drop_role(iam, name: str, managed: tuple = ()) -> None:
    detach = [lambda p=p: iam.detach_role_policy(RoleName=name, PolicyArn=p) for p in managed]
    for fn in [lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline")] + detach:
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
    iam.delete_role(RoleName=name)


def _run_count(glue, workflow: str) -> int:
    """How many runs this workflow has, through Glue's own reader. GetWorkflowRuns raises
    EntityNotFoundException until a workflow has run, so that code means zero runs."""
    try:
        total = 0
        for page in glue.get_paginator("get_workflow_runs").paginate(Name=workflow):
            total += len(page["Runs"])
        return total
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "EntityNotFoundException":
            # The workflow itself is asserted to exist before this is ever called, so this can
            # only mean "no runs yet".
            return 0
        raise


def _workflow(ctx, glue, name: str, job_name: str, batch_size: int) -> str:
    """A workflow whose only starting trigger is an EVENT trigger with the given batch size."""
    glue.create_workflow(Name=name, Description="sim2real-behav glue event batching",
                         Tags={"sim2real": "glue-event-batching"})
    ctx.on_cleanup(lambda: glue.delete_workflow(Name=name))
    ctx.on_cleanup(lambda: _stop_runs(glue, name))

    trigger = f"{name}-evt"
    batching = {"BatchSize": batch_size}
    if batch_size > 1:
        batching["BatchWindow"] = _BATCH_WINDOW_S
    glue.create_trigger(
        Name=trigger,
        Type="EVENT",
        WorkflowName=name,
        Actions=[{"JobName": job_name}],
        EventBatchingCondition=batching,
        Tags={"sim2real": "glue-event-batching"},
    )
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=trigger))

    # StartTrigger refuses an EVENT trigger ("Trigger Type EVENT cannot be started"); it is live for
    # EventBridge deliveries once GetTrigger reports CREATED, so StopTrigger is never called either.
    got = _poll(
        lambda: glue.get_trigger(Name=trigger)["Trigger"],
        lambda t: t.get("State") == "CREATED",
        timeout_s=120.0,
        what=f"EVENT trigger {trigger!r} reaching CREATED",
    )
    assert got["EventBatchingCondition"]["BatchSize"] == batch_size, (
        f"trigger {trigger!r} must carry BatchSize {batch_size}; GetTrigger reports "
        f"{got.get('EventBatchingCondition')!r}"
    )
    assert got["Type"] == "EVENT", (
        f"trigger {trigger!r} must be an EVENT trigger, GetTrigger reports {got['Type']!r}"
    )
    return trigger


def _stop_runs(glue, workflow: str) -> None:
    """Stop any in-flight run so DeleteWorkflow is not refused. Bounded; never raises past its
    own tolerated codes, because it runs as cleanup."""
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            runs = glue.get_workflow_runs(Name=workflow)["Runs"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityNotFoundException":
                return
            raise
        live = [r for r in runs if r["Status"] == "RUNNING"]
        if not live:
            return
        for r in live:
            try:
                glue.stop_workflow_run(Name=workflow, RunId=r["WorkflowRunId"])
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") not in (
                        "IllegalWorkflowStateException", "EntityNotFoundException"):
                    raise
        time.sleep(5.0)


def _warm_up(ctx, ev, glue, rule, workflow, workflow_arn, role_arn, stem) -> None:
    """Re-emit to a warm-up rule until its own workflow runs: an invocation before events_role
    propagates fails with FAILED_TO_ASSUME_ROLE, so deliveries 1-3 wait for a proven delivery."""
    ev.put_rule(Name=rule, State="ENABLED", EventPattern=json.dumps(
        {"source": [_SOURCE], "detail-type": [_WARM_DETAIL_TYPE]}))
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))
    put = _poll(
        lambda: ev.put_targets(Rule=rule, Targets=[
            {"Id": "warm", "Arn": workflow_arn, "RoleArn": role_arn}]),
        lambda r: r["FailedEntryCount"] == 0,
        timeout_s=_ROLE_PROPAGATION_TIMEOUT_S, interval_s=2.0,
        what="put_targets accepting the warm-up workflow target",
    )
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["warm"]))
    assert put["FailedEntryCount"] == 0, f"warm-up put_targets failed: {put.get('FailedEntries')!r}"
    left = ctx.time_left()
    budget = _ROLE_PROPAGATION_TIMEOUT_S + _RUN_APPEARS_BUDGET_S
    deadline = time.monotonic() + (budget if left is None else min(budget, max(0.0, left - 5)))
    polls = 0
    while True:
        if polls % 5 == 0:  # one warm-up event every 10 s
            resp = ev.put_events(Entries=[{"Source": _SOURCE, "DetailType": _WARM_DETAIL_TYPE,
                                           "Detail": json.dumps({"stem": stem})}])
            assert resp["FailedEntryCount"] == 0, f"warm-up put_events failed: {resp['Entries']!r}"
        if _run_count(glue, workflow) >= 1:
            return
        assert time.monotonic() < deadline, (
            f"no warm-up delivery to {workflow!r} produced a workflow run within {budget:.0f}s"
        )
        polls += 1
        time.sleep(2.0)


@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Glue EVENT trigger with BatchSize=3 starts no workflow run on the first two EventBridge
    deliveries and exactly one on the third, while a BatchSize=1 twin on the same rule runs at once,
    proving delivery worked while the batched workflow stayed at zero.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_EventBatchingCondition.html"""
    ev = ctx.client("events")
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    stem = ctx.unique_name("sim2real-behav-glue-batch-")

    # --- a Glue service role, created here ----------------------------------------------------
    glue_role = _role(ctx, iam, f"{stem}-glue", "glue.amazonaws.com",
                      {"Version": "2012-10-17",
                       "Statement": [{"Effect": "Allow", "Action": "logs:*", "Resource": "*"}]},
                      managed=(_GLUE_SERVICE_POLICY,))

    # --- the cheapest possible job. Its script is absent on purpose. -------------------------
    job = f"{stem}-job"
    glue.create_job(
        Name=job,
        Role=glue_role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9",
                 "ScriptLocation": f"s3://{_ABSENT_SCRIPT_BUCKET_HINT}-{account}/noop.py"},
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real": "glue-event-batching"},
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job))

    batched = f"{stem}-batched"
    twin = f"{stem}-twin"
    warm = f"{stem}-warm"
    _workflow(ctx, glue, batched, job, _BATCH_SIZE)
    _workflow(ctx, glue, twin, job, 1)
    _workflow(ctx, glue, warm, job, 1)

    for name in (batched, twin):
        assert glue.get_workflow(Name=name)["Workflow"]["Name"] == name, (
            f"workflow {name!r} must exist before any delivery, or a zero run count would be "
            f"ambiguous"
        )

    # --- one rule, both workflows as targets -------------------------------------------------
    workflow_arns = {
        name: f"arn:aws:glue:{ctx.region}:{account}:workflow/{name}"
        for name in (batched, twin)
    }
    warm_arn = f"arn:aws:glue:{ctx.region}:{account}:workflow/{warm}"
    events_role = _role(
        ctx, iam, f"{stem}-events", "events.amazonaws.com",
        {"Version": "2012-10-17",
         "Statement": [{"Effect": "Allow", "Action": "glue:notifyEvent",
                        "Resource": sorted([*workflow_arns.values(), warm_arn])}]},
        managed=_EVENTS_TARGET_POLICIES,
    )

    rule = f"{stem}-rule"
    ev.put_rule(Name=rule, State="ENABLED",
                EventPattern=json.dumps({"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}))
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))

    targets = [{"Id": "batched", "Arn": workflow_arns[batched], "RoleArn": events_role},
               {"Id": "twin", "Arn": workflow_arns[twin], "RoleArn": events_role}]
    put = _poll(
        lambda: ev.put_targets(Rule=rule, Targets=targets),
        lambda r: r["FailedEntryCount"] == 0,
        timeout_s=_ROLE_PROPAGATION_TIMEOUT_S,
        what="put_targets accepting the Glue workflow targets and the freshly minted role",
    )
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["batched", "twin"]))
    assert put["FailedEntryCount"] == 0, (
        f"put_targets reported {put['FailedEntryCount']} failures: {put.get('FailedEntries')!r}"
    )
    configured = {t["Id"]: t["Arn"] for t in ev.list_targets_by_rule(Rule=rule)["Targets"]}
    assert configured == {"batched": workflow_arns[batched], "twin": workflow_arns[twin]}, (
        f"the rule must target both workflows; ListTargetsByRule reports {configured!r}"
    )
    _warm_up(ctx, ev, glue, f"{stem}-warm-rule", warm, warm_arn, events_role, stem)

    def _emit(n: int) -> None:
        resp = ev.put_events(Entries=[{
            "Source": _SOURCE, "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"seq": n, "stem": stem}),
        }])
        assert resp["FailedEntryCount"] == 0, (
            f"put_events for delivery {n} reported {resp['FailedEntryCount']} failures: "
            f"{resp['Entries']!r}"
        )

    # --- deliveries 1 and 2: the twin must run, the batched workflow must not -----------------
    _emit(1)
    _emit(2)
    twin_seen_at = time.monotonic()
    _poll(
        lambda: _run_count(glue, twin),
        lambda n: n >= 1,
        timeout_s=_RUN_APPEARS_BUDGET_S,
        what=f"the BatchSize=1 twin workflow {twin!r} starting a run from the first two "
             f"deliveries",
    )
    twin_latency_s = time.monotonic() - twin_seen_at
    # Calibrated before the window is held: the twin's latency measures delivery-to-run on the
    # same wiring, so the absence window is 5x it, checked against 3x the third delivery's later.
    absence_s = max(_ABSENCE_FLOOR_S, 5.0 * twin_latency_s)
    assert absence_s < _BATCH_WINDOW_S, (
        f"the twin took {twin_latency_s:.1f}s to turn a delivery into a workflow run, so the "
        f"{absence_s:.0f}s absence window would reach the {_BATCH_WINDOW_S}s BatchWindow and could "
        f"not tell the batch size from the window"
    )
    assert _run_count(glue, batched) == 0, (
        f"the BatchSize={_BATCH_SIZE} workflow {batched!r} already has "
        f"{_run_count(glue, batched)} run(s) after only 2 deliveries, while its BatchSize=1 twin "
        f"has {_run_count(glue, twin)} — the batch size suppressed nothing"
    )

    # Hold the absence, with the twin's run as the live proof that delivery was working.
    absence_deadline = time.monotonic() + absence_s
    while time.monotonic() < absence_deadline:
        got = _run_count(glue, batched)
        assert got == 0, (
            f"the BatchSize={_BATCH_SIZE} workflow {batched!r} started {got} run(s) on 2 "
            f"deliveries, {time.monotonic() - twin_seen_at:.0f}s in; BatchWindow is "
            f"{_BATCH_WINDOW_S}s so the window cannot be what fired it"
        )
        time.sleep(2.0)
    assert _run_count(glue, batched) == 0, (
        f"the BatchSize={_BATCH_SIZE} workflow must have zero runs after 2 of 3 deliveries; it "
        f"has {_run_count(glue, batched)}"
    )
    twin_runs_at_absence_end = _run_count(glue, twin)
    assert twin_runs_at_absence_end >= 1, (
        f"the twin's run must still be visible for the absence to be attributable; "
        f"GetWorkflowRuns now reports {twin_runs_at_absence_end}"
    )

    # --- delivery 3: exactly one run, and the window we held was long enough ------------------
    third_at = time.monotonic()
    _emit(3)
    _poll(
        lambda: _run_count(glue, batched),
        lambda n: n >= 1,
        timeout_s=_RUN_APPEARS_BUDGET_S,
        what=f"the BatchSize={_BATCH_SIZE} workflow {batched!r} starting a run on the third "
             f"delivery",
    )
    third_latency_s = time.monotonic() - third_at
    assert 3.0 * third_latency_s <= absence_s, (
        f"the third delivery took {third_latency_s:.1f}s to produce a run, so the absence window "
        f"this check held ({absence_s:.0f}s) is under 3x that; the twin measured "
        f"{twin_latency_s:.1f}s on the same wiring, so the window was too short to trust"
    )
    final = _run_count(glue, batched)
    assert final == 1, (
        f"three deliveries against BatchSize={_BATCH_SIZE} must produce exactly one run; "
        f"GetWorkflowRuns reports {final} (the twin, at BatchSize=1, reports "
        f"{_run_count(glue, twin)} from the same deliveries)"
    )
    run_record = glue.get_workflow_runs(Name=batched)["Runs"][0]
    assert run_record["Name"] == batched, (
        f"the run must belong to {batched!r}; GetWorkflowRuns reports {run_record['Name']!r}"
    )
    assert run_record["WorkflowRunId"], (
        f"the run must carry a run id: {run_record!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
