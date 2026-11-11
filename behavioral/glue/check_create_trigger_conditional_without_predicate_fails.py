"""create-trigger-conditional-without-predicate-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-trigger-conditional-without-predicate-fails"
GROUP = 'overly-permissive'
SERVICES = ['glue']

def _delete_role(iam, name):
    try:
        for pol in iam.list_attached_role_policies(RoleName=name).get("AttachedPolicies", []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=name)


def _glue_role_arn(ctx):
    """Create a self-cleaning Glue-assumable IAM role and return its ARN."""
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
    """Newly-created IAM roles take time to propagate; Glue's AssumeRole probe on a
    brand-new role commonly fails for a few seconds after creation."""
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
    _retry_call(lambda: glue.create_job(
        Name=name,
        Role=role,
        Command={"Name": "pythonshell", "PythonVersion": "3.9", "ScriptLocation": script},
        MaxCapacity=0.0625,
        Timeout=10,
        Tags={"sim2real": CHECK},
    ))
    ctx.on_cleanup(lambda: glue.delete_job(JobName=name))
    return name

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """create_trigger of Type=CONDITIONAL without a Predicate raises InvalidInputException,
    the account is otherwise able to create CONDITIONAL triggers, and the rejected call
    leaves no trigger behind."""
    glue = ctx.client("glue")
    role = _glue_role_arn(ctx)
    watched_job = _create_job(ctx, glue, role)
    action_job = _create_job(ctx, glue, role)

    # Positive control: an otherwise-identical CONDITIONAL trigger WITH a Predicate
    # must succeed on this account/role, so the rejection below is provably about the
    # missing Predicate and not a general inability to create CONDITIONAL triggers.
    control_name = ctx.unique_name("sim2real-behav-trigger-control-")
    glue.create_trigger(
        Name=control_name,
        Type="CONDITIONAL",
        Actions=[{"JobName": action_job}],
        Predicate={
            "Conditions": [
                {"LogicalOperator": "EQUALS", "JobName": watched_job, "State": "SUCCEEDED"}
            ],
            "Logical": "AND",
        },
    )
    ctx.on_cleanup(lambda: glue.delete_trigger(Name=control_name))
    control = glue.get_trigger(Name=control_name)["Trigger"]
    assert control["Type"] == "CONDITIONAL" and "Predicate" in control, (
        f"positive control: expected a persisted CONDITIONAL trigger with a Predicate, got {control}"
    )

    trigger_name = ctx.unique_name("sim2real-behav-trigger-")
    try:
        glue.create_trigger(
            Name=trigger_name,
            Type="CONDITIONAL",
            Actions=[{"JobName": action_job}],
            # Predicate intentionally omitted: required for CONDITIONAL triggers.
        )
        code, message = None, None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    if code is None:
        ctx.on_cleanup(lambda: glue.delete_trigger(Name=trigger_name))
    assert code == "InvalidInputException", (
        f"expected InvalidInputException for CONDITIONAL trigger missing Predicate, got {code}"
    )
    expected = "Predicate cannot be null or empty"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent read at the destination: the rejected create must not have left a
    # trigger behind.
    get_code, get_message = None, None
    try:
        glue.get_trigger(Name=trigger_name)
    except ClientError as exc:
        get_code = exc.response.get("Error", {}).get("Code")
        get_message = exc.response.get("Error", {}).get("Message")
    assert get_code == "EntityNotFoundException", (
        f"expected no trigger to exist after the rejected create, got code={get_code}"
    )
    assert get_message == "Trigger not found.", f"unexpected not-found message {get_message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
