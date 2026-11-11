"""workflow-run-properties-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "workflow-run-properties-roundtrip"
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
    """Create a pythonshell job (cheapest run profile); track for cleanup.

    CreateJob probes that the role trusts glue.amazonaws.com, so a role created
    moments earlier by this same check can still fail that probe until IAM
    propagates it. Retry within a bounded window instead of a blind sleep.
    """
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    deadline = time.time() + 30
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
        except ClientError as exc:
            err = exc.response.get("Error", {})
            not_yet_assumable = (
                err.get("Code") == "InvalidInputException"
                and "assumerole" in err.get("Message", "").lower()
            )
            if not not_yet_assumable or time.time() >= deadline:
                raise
            time.sleep(3)
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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RunProperties supplied to start_workflow_run are retrievable and mutable mid-run."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    workflow_name = ctx.unique_name("sim2real-behav-wf-")
    glue.create_workflow(
        Name=workflow_name,
        DefaultRunProperties={"env": "default", "shared": "yes"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: glue.delete_workflow(Name=workflow_name))
    job_name = _create_job(ctx, glue, role)
    trigger_name = ctx.unique_name("sim2real-behav-trigger-")
    glue.create_trigger(
        Name=trigger_name,
        Type="ON_DEMAND",
        WorkflowName=workflow_name,
        Actions=[{"JobName": job_name}],
        Tags={"sim2real": CHECK},
    )
    _track_trigger(ctx, glue, name=trigger_name)

    wf = glue.get_workflow(Name=workflow_name)["Workflow"]
    assert wf["DefaultRunProperties"]["env"] == "default", (
        f"DefaultRunProperties not persisted on the workflow: {wf}"
    )

    run_id = glue.start_workflow_run(
        Name=workflow_name, RunProperties={"env": "test", "batch": "42"}
    )["RunId"]

    props = glue.get_workflow_run_properties(Name=workflow_name, RunId=run_id)["RunProperties"]
    assert props.get("env") == "test", (
        f"per-run RunProperties must override DefaultRunProperties: {props}"
    )
    assert props.get("batch") == "42", f"unexpected RunProperties: {props}"

    glue.put_workflow_run_properties(
        Name=workflow_name, RunId=run_id, RunProperties={"env": "test", "batch": "43"}
    )
    updated = glue.get_workflow_run_properties(Name=workflow_name, RunId=run_id)["RunProperties"]
    assert updated.get("batch") == "43", (
        f"PutWorkflowRunProperties did not persist the new value: {updated}"
    )

    glue.update_workflow(Name=workflow_name, Description="updated description")
    assert (
        glue.get_workflow(Name=workflow_name)["Workflow"]["Description"] == "updated description"
    ), "UpdateWorkflow did not persist Description"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
