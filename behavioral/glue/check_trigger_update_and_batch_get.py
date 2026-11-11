"""trigger-update-and-batch-get."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trigger-update-and-batch-get"
GROUP = 'trigger'
SERVICES = ['glue']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateTrigger mutates Schedule/Description; ListTriggers/BatchGetTriggers reflect it;
    after DeleteTrigger both GetTrigger and UpdateTrigger refuse with EntityNotFoundException."""
    glue = ctx.client("glue")
    role_arn = _service_role_arn(ctx)
    job_name = ctx.unique_name("sim2real-behav-glue-job-")
    trigger_name = ctx.unique_name("sim2real-behav-glue-trigger-")
    _create_job(ctx, glue, job_name, role_arn)

    glue.create_trigger(
        Name=trigger_name,
        Type="SCHEDULED",
        Schedule="cron(0 12 * * ? *)",
        Description="v1",
        Actions=[{"JobName": job_name}],
        StartOnCreation=False,
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_trigger_quiet(glue, trigger_name))

    glue.update_trigger(
        Name=trigger_name,
        TriggerUpdate={
            "Description": "v2",
            "Schedule": "cron(0 18 * * ? *)",
            "Actions": [{"JobName": job_name, "Arguments": {"--mode": "batch"}}],
        },
    )
    trig = glue.get_trigger(Name=trigger_name)["Trigger"]
    assert trig["Description"] == "v2", f"UpdateTrigger did not persist Description: {trig}"
    assert trig["Schedule"] == "cron(0 18 * * ? *)", (
        f"UpdateTrigger did not persist Schedule: {trig}"
    )
    assert trig["Actions"][0]["Arguments"]["--mode"] == "batch", (
        f"UpdateTrigger did not persist Action Arguments: {trig}"
    )

    assert trigger_name in glue.list_triggers()["TriggerNames"], (
        "trigger missing from ListTriggers"
    )
    assert trigger_name in {t["Name"] for t in glue.get_triggers()["Triggers"]}, (
        "trigger missing from GetTriggers"
    )

    batch = glue.batch_get_triggers(TriggerNames=[trigger_name, "does-not-exist-trigger"])
    assert [t["Name"] for t in batch["Triggers"]] == [trigger_name], (
        f"BatchGetTriggers must return only the known trigger, got {batch['Triggers']!r}"
    )
    assert batch["TriggersNotFound"] == ["does-not-exist-trigger"], (
        f"unknown trigger must be reported in TriggersNotFound: {batch['TriggersNotFound']}"
    )

    glue.delete_trigger(Name=trigger_name)

    # DeleteTrigger is asynchronous: the trigger first enters DELETING and only
    # then disappears, so the terminal contract has to be polled for. Only the
    # specific EntityNotFoundException counts as "gone" -- any other error (a
    # throttle, a transient 500) must not be read as the same verdict.
    def probe_gone():
        try:
            glue.get_trigger(Name=trigger_name)
            return {}
        except ClientError as exc:
            return exc.response.get("Error", {})

    final = _poll_until(
        probe_gone,
        lambda e: e.get("Code") == "EntityNotFoundException",
        timeout_s=180,
        interval_s=3,
        description="deleted trigger reaching EntityNotFoundException",
    )
    assert final["Code"] == "EntityNotFoundException", (
        f"deleted trigger must eventually 404 with EntityNotFoundException, got {final!r}"
    )
    expected = "Trigger not found."
    assert final.get("Message") == expected, (
        f"expected message {expected!r}, got {final.get('Message')!r}"
    )
    assert trigger_name not in glue.list_triggers()["TriggerNames"], (
        "deleted trigger must not appear in ListTriggers"
    )

    # UpdateTrigger on the deleted name, with a TriggerUpdate that carries the Actions it
    # requires, is refused as a missing trigger, the same refusal GetTrigger gives.
    try:
        glue.update_trigger(
            Name=trigger_name,
            TriggerUpdate={"Description": "v3", "Actions": [{"JobName": job_name}]},
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError("UpdateTrigger on a deleted trigger SUCCEEDED; AWS rejects it")
    dead_update_code, dead_update_message = err.get("Code"), err.get("Message")
    assert dead_update_code == "EntityNotFoundException", (
        f"UpdateTrigger on a deleted trigger must fail with EntityNotFoundException, got {dead_update_code!r}"
    )
    expected = "Trigger not found."
    assert dead_update_message == expected, (
        f"expected message {expected!r}, got {dead_update_message!r}"
    )


# ===== helpers =====
_GLUE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "glue.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_GLUE_SERVICE_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"


def _quiet(fn, not_found="EntityNotFoundException"):
    """Teardown call that tolerates only the resource already being gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != not_found:
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _retry_call(fn, timeout_s=90.0, interval_s=5.0, retry_codes=("AccessDeniedException", "InvalidInputException")):
    """Retry fn() while IAM PassRole propagation is still catching up.

    Glue authorizes iam:PassRole before it accepts a job definition, and IAM is eventually
    consistent, so a fresh role can bounce a job/trigger create with these codes for a short
    window after AttachRolePolicy returns. Bounded retry on that window, never a fixed sleep.
    """
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


def _service_role_arn(ctx) -> str:
    """Create a real Glue-assumable role and return its ARN."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-glue-role-")[:64]
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_GLUE_TRUST_POLICY),
        Description="SimParity behavioral fidelity test role",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup():
        _quiet(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn=_GLUE_SERVICE_POLICY_ARN
            ),
            "NoSuchEntity",
        )
        _quiet(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity")

    ctx.on_cleanup(_cleanup)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_GLUE_SERVICE_POLICY_ARN)

    for _ in range(20):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(1)
    return arn


def _create_job(ctx, glue, name, role_arn, **extra) -> None:
    _retry_call(
        lambda: glue.create_job(
            Name=name,
            Role=role_arn,
            Command={
                "Name": "glueetl",
                "ScriptLocation": "s3://example-bucket/scripts/job.py",
            },
            Tags={"sim2real": CHECK},
            **extra,
        )
    )
    ctx.on_cleanup(lambda: _quiet(lambda: glue.delete_job(JobName=name)))


def _delete_trigger_quiet(glue, name):
    # the trigger is created with StartOnCreation=False and never activated, so there is nothing to stop
    _quiet(lambda: glue.delete_trigger(Name=name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
