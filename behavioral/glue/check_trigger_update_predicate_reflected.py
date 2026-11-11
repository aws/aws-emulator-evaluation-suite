"""trigger-update-predicate-reflected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trigger-update-predicate-reflected"
GROUP = 'trigger'
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

def _retry_call(fn, timeout_s=60.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    """Bounded retry over the just-created role's IAM propagation lag: Glue's
    AssumeRole probe on CreateJob fails if we race ahead of it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    _retry_call(
        lambda: glue.create_job(
            Name=name,
            Role=role,
            Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
            MaxCapacity=0.0625,
            Timeout=10,
            Tags={"sim2real": CHECK},
        )
    )
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
    """update_trigger on a CONDITIONAL trigger replaces the Predicate and it is visible on get_trigger."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    name = ctx.unique_name("sim2real-behav-trigger-")
    watched_job = _create_job(ctx, glue, role)
    action_job = _create_job(ctx, glue, role)

    glue.create_trigger(
        Name=name,
        Type="CONDITIONAL",
        Actions=[{"JobName": action_job}],
        Predicate={
            "Conditions": [
                {"LogicalOperator": "EQUALS", "JobName": watched_job, "State": "SUCCEEDED"}
            ],
            "Logical": "AND",
        },
        Tags={"sim2real": CHECK},
    )
    _track_trigger(ctx, glue, name)

    new_watched_job = _create_job(ctx, glue, role)
    # TriggerUpdate is a full replacement, not a patch: real Glue rejects an
    # update that omits Actions.
    glue.update_trigger(
        Name=name,
        TriggerUpdate={
            "Actions": [{"JobName": action_job}],
            "Predicate": {
                "Conditions": [
                    {"LogicalOperator": "EQUALS", "JobName": new_watched_job, "State": "FAILED"}
                ],
                "Logical": "AND",
            },
        },
    )

    resp = glue.get_trigger(Name=name)
    conditions = resp["Trigger"]["Predicate"]["Conditions"]
    assert conditions[0]["JobName"] == new_watched_job, (
        f"expected updated predicate to watch {new_watched_job!r}, "
        f"get_trigger still shows {conditions[0]['JobName']!r}"
    )
    assert conditions[0]["State"] == "FAILED", (
        f"expected updated predicate state FAILED, get_trigger shows {conditions[0]['State']!r}"
    )
    assert resp["Trigger"]["Actions"][0]["JobName"] == action_job, (
        f"expected Actions to still reference {action_job!r}, "
        f"get_trigger shows {resp['Trigger']['Actions'][0]['JobName']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
