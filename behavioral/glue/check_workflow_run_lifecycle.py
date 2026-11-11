"""workflow-run-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workflow-run-lifecycle"
GROUP = 'workflow'
SERVICES = ['glue']

def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _glue_role_arn(ctx):
    """Create a Glue-assumable IAM role this check owns, with its cleanup registered at once."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "glue.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="SimParity behavioral fidelity check role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.attach_role_policy(
        RoleName=name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole",
    )
    return resp["Role"]["Arn"]

def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    # CreateJob validates the Role against IAM, so it raises while a just-created
    # role's trust is still propagating; this bounded retry is the wait.
    deadline = time.monotonic() + 120
    while True:
        try:
            glue.create_job(
                Name=name,
                Role=role,
                Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
                MaxCapacity=0.0625,
                Timeout=10,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] not in ("InvalidInputException",
                                                       "AccessDeniedException") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name

def _stop_trigger_quiet(glue, name):
    """Teardown: StopTrigger refuses a trigger that is not started, which is fine here."""
    try:
        glue.stop_trigger(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "InvalidInputException",
            "EntityNotFoundException",
        ):
            raise


def _track_trigger(ctx, glue, name):
    # LIFO: the stop runs before delete_trigger.
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=name))
    ctx.on_cleanup(lambda: _stop_trigger_quiet(glue, name))

def _poll(fn, pred, timeout_s, interval_s):
    deadline = time.time() + timeout_s
    val = fn()
    while not pred(val):
        if time.time() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """start_workflow_run produces a run that transitions to a terminal WorkflowRunStatus.

    A Glue workflow is only runnable once it has a *starting* trigger (an ON_DEMAND
    trigger bound to the workflow); start_workflow_run on a bare workflow is rejected.
    """
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    workflow_name = ctx.unique_name("sim2real-behav-wf-")
    glue.create_workflow(
        Name=workflow_name,
        Description="behavioral test workflow",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_workflow(Name=workflow_name))
    job_name = _create_job(ctx, glue, role)

    # A bare workflow has no entry point and must be rejected.
    try:
        glue.start_workflow_run(Name=workflow_name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError("start_workflow_run on a bare workflow SUCCEEDED; AWS rejects it")
    code, message = err.get("Code"), err.get("Message")
    assert code == "InvalidInputException", (
        f"start_workflow_run on a workflow with no starting trigger must be rejected, got {code}"
    )
    expected = f"Workflow {workflow_name} doesn't have any starting trigger."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    trigger_name = ctx.unique_name("sim2real-behav-trigger-")
    glue.create_trigger(
        Name=trigger_name,
        Type="ON_DEMAND",
        WorkflowName=workflow_name,
        Actions=[{"JobName": job_name}],
        Tags={"sim2real": CHECK},
    )
    _track_trigger(ctx, glue, name=trigger_name)

    graph = glue.get_workflow(Name=workflow_name, IncludeGraph=True)["Workflow"]
    node_types = sorted(n["Type"] for n in graph["Graph"]["Nodes"])
    assert node_types == ["JOB", "TRIGGER"], (
        f"workflow graph must contain the trigger and its job node, got {node_types}"
    )

    run_id = glue.start_workflow_run(Name=workflow_name)["RunId"]

    terminal = {"COMPLETED", "STOPPED", "ERROR"}
    final_status = _poll(
        lambda: glue.get_workflow_run(Name=workflow_name, RunId=run_id)["Run"]["Status"],
        lambda s: s in terminal,
        timeout_s=240,
        interval_s=5,
    )
    assert final_status in terminal, f"workflow run never reached terminal status: {final_status}"

    run = glue.get_workflow_run(Name=workflow_name, RunId=run_id)["Run"]
    assert run["WorkflowRunId"] == run_id, (
        f"GetWorkflowRun returned a mismatched RunId: expected {run_id}, got {run['WorkflowRunId']}"
    )
    assert run["Name"] == workflow_name, (
        f"GetWorkflowRun returned a mismatched workflow Name: expected {workflow_name}, got {run['Name']}"
    )

    runs = glue.get_workflow_runs(Name=workflow_name)["Runs"]
    assert run_id in {r["WorkflowRunId"] for r in runs}, "GetWorkflowRuns must include the run"

    pages = glue.get_paginator("list_workflows").paginate()
    listed = [name for page in pages for name in page["Workflows"]]
    assert workflow_name in listed, "workflow missing from ListWorkflows"

    batch = glue.batch_get_workflows(Names=[workflow_name, "does-not-exist-workflow"])
    assert [w["Name"] for w in batch["Workflows"]] == [workflow_name], (
        f"BatchGetWorkflows should only resolve the existing workflow: {batch['Workflows']}"
    )
    assert batch["MissingWorkflows"] == ["does-not-exist-workflow"], (
        f"unknown workflow must be reported in MissingWorkflows: {batch['MissingWorkflows']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
