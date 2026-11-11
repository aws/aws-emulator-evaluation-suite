"""trigger-create-get-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trigger-create-get-delete"
GROUP = 'trigger'
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
    """Create a dedicated, self-cleaning Glue-assumable IAM role and return its ARN."""
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

def _create_with_role_retry(fn, timeout_s=90, interval_s=5.0):
    """A role just created by this check may not yet be assumable when Glue
    validates it inline; retry until IAM propagation catches up."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            msg = str(exc)
            transient = "is not authorized" in msg or "AssumeRole" in msg or "InvalidInputException" in msg
            if transient and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise

def _create_job(ctx, glue, role):
    """Create a pythonshell job (cheapest run profile); track for cleanup."""
    name = ctx.unique_name("sim2real-behav-job-")
    script = f"s3://{ctx.unique_name('sim2real-behav-glue-scripts-')}/scripts/etl.py"
    _create_with_role_retry(
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

def _ignore_missing(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "EntityNotFoundException":
            raise


def _track_trigger(ctx, glue, name):
    # LIFO: stop_trigger runs before delete_trigger; a trigger already deleted is not a leak.
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.delete_trigger(Name=name)))
    ctx.on_cleanup(lambda: _ignore_missing(lambda: glue.stop_trigger(Name=name)))

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create_trigger (ON_DEMAND) starts in CREATED state -> get_trigger reflects it -> delete_trigger removes it."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-behav-trigger-")
    job_name = _create_job(ctx, glue, _glue_role_arn(ctx))

    glue.create_trigger(
        Name=name,
        Type="ON_DEMAND",
        Actions=[{"JobName": job_name}],
        Tags={"sim2real": CHECK},
    )
    _track_trigger(ctx, glue, name)

    resp = glue.get_trigger(Name=name)
    trig = resp["Trigger"]
    assert trig["Name"] == name
    assert trig["Actions"][0]["JobName"] == job_name
    assert trig["State"] == "CREATED", trig["State"]

    glue.delete_trigger(Name=name)

    # DeleteTrigger is asynchronous: the trigger may stay readable (DELETING) for a while.
    # Poll until it is gone and grade the terminal not-found refusal.
    code, message = None, None
    deadline = time.monotonic() + 180
    while True:
        try:
            glue.get_trigger(Name=name)
            code, message = None, None
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message")
        if code == "EntityNotFoundException" or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert code == "EntityNotFoundException", f"expected EntityNotFoundException, got {code}"
    expected = "Trigger not found."
    assert message == expected, f"expected GetTrigger message {expected!r}, got {message!r}"

    # A deleted trigger is not just unreadable -- it must also reject a mutation.
    try:
        glue.start_trigger(Name=name)
        raise AssertionError("expected StartTrigger on a deleted trigger to fail")
    except ClientError as exc:
        mutate_code = exc.response.get("Error", {}).get("Code")
        mutate_message = exc.response.get("Error", {}).get("Message")
    assert mutate_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException from StartTrigger on a deleted trigger, got {mutate_code}"
    )
    expected = "Trigger not found."
    assert mutate_message == expected, f"expected StartTrigger message {expected!r}, got {mutate_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
