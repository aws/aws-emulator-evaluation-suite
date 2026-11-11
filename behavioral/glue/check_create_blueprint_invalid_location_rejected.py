"""create-blueprint-invalid-location-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-blueprint-invalid-location-rejected"
GROUP = "overly-permissive"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """StartBlueprintRun on a blueprint that never reached ACTIVE raises
    IllegalBlueprintStateException and creates no run; the blueprint then terminates FAILED.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_StartBlueprintRun.html
    """
    glue = ctx.client("glue")
    role_arn = _create_glue_assumable_role(ctx)

    name = ctx.unique_name("sim2real-glue-bp-")
    bucket = ctx.unique_name("sim2real-glue-bp-nonexistent-")
    # CreateBlueprint is asynchronous (CREATING -> ACTIVE|FAILED); an unresolvable location
    # guarantees the immediate run sees CREATING or FAILED, never ACTIVE.
    glue.create_blueprint(Name=name, BlueprintLocation=f"s3://{bucket}/blueprint.zip")

    def _cleanup():
        try:
            glue.delete_blueprint(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    code, message = _error(lambda: glue.start_blueprint_run(BlueprintName=name, RoleArn=role_arn))
    assert code == "IllegalBlueprintStateException", (
        f"expected IllegalBlueprintStateException, got {code}"
    )
    assert message == f"No active definition found for Blueprint: {name}", (
        f"unexpected StartBlueprintRun message: {message!r}"
    )

    # Effect absent: the blueprint is unaffected (still exists, no run was created).
    blueprint = glue.get_blueprint(Name=name)["Blueprint"]
    assert blueprint["Name"] == name, f"expected blueprint name {name}, got {blueprint.get('Name')}"
    assert blueprint["Status"] in ("CREATING", "FAILED"), (
        f"expected blueprint to still be non-ACTIVE, got {blueprint['Status']}"
    )

    # Effect absent, independent side-channel: the rejected call created no run.
    runs = glue.get_blueprint_runs(BlueprintName=name)["BlueprintRuns"]
    assert runs == [], f"expected no blueprint runs after rejection, got {runs}"

    # The location can never resolve, so ACTIVE is unreachable -- confirm the
    # blueprint actually lands on the only terminal state available to it,
    # rather than resting on a single immediate read that could catch it
    # mid-CREATING.
    final_status = _poll_until(
        lambda: glue.get_blueprint(Name=name)["Blueprint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert final_status == "FAILED", f"expected blueprint to terminate FAILED, got {final_status}"

    # Positive control: the rejection is specific to starting a run in an illegal state, not a
    # blanket failure; delete still works and the blueprint is then gone.
    glue.delete_blueprint(Name=name)
    not_found_code, not_found_message = _error(lambda: glue.get_blueprint(Name=name))
    assert not_found_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after delete, got {not_found_code}"
    )
    assert not_found_message == "Blueprint with given name not found.", (
        f"unexpected GetBlueprint message: {not_found_message!r}"
    )



def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises rather than
    reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_glue_assumable_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-bp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
