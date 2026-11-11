"""start-blueprint-run-illegal-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-blueprint-run-illegal-state-rejected"
GROUP = "negative-classes"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartBlueprintRun on a blueprint whose S3 location can never resolve (CREATING or FAILED,
    never ACTIVE) raises IllegalBlueprintStateException and creates no run, while GetBlueprint and
    DeleteBlueprint on it still succeed."""
    glue = ctx.client("glue")
    role_arn = _create_glue_assumable_role(ctx)

    name = ctx.unique_name("sim2real-bp-")
    bucket = ctx.unique_name("sim2real-nonexistent-bucket-")
    glue.create_blueprint(Name=name, BlueprintLocation=f"s3://{bucket}/blueprint.zip")

    def _cleanup():
        try:
            glue.delete_blueprint(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    code, message = _refusal(lambda: glue.start_blueprint_run(BlueprintName=name, RoleArn=role_arn))
    assert code == "IllegalBlueprintStateException", (
        f"expected IllegalBlueprintStateException, got {code!r}"
    )
    assert message == f"No active definition found for Blueprint: {name}", message

    status_after_reject = glue.get_blueprint(Name=name)["Blueprint"]["Status"]
    assert status_after_reject != "ACTIVE", (
        f"blueprint reached ACTIVE despite the rejected run, status={status_after_reject!r}"
    )

    # Effect absent: the rejected call created no blueprint run.
    runs = glue.get_blueprint_runs(BlueprintName=name)
    assert runs["BlueprintRuns"] == [], (
        f"expected no blueprint runs after the rejected StartBlueprintRun, found {runs['BlueprintRuns']!r}"
    )

    # Wait the blueprint out to its (only reachable) terminal state.
    final_status = _poll_until(
        lambda: glue.get_blueprint(Name=name)["Blueprint"]["Status"],
        lambda status: status in ("ACTIVE", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    assert final_status == "FAILED", f"expected the blueprint to settle on FAILED, got {final_status!r}"

    # Positive control: normal, valid operations against this same
    # blueprint resource succeed -- the rejection above is specific to
    # starting a run in an illegal state, not a blanket failure of the
    # Blueprint API for this resource.
    described = glue.get_blueprint(Name=name, IncludeBlueprint=False)
    assert described["Blueprint"]["Name"] == name, (
        f"expected GetBlueprint to return {name!r}, got {described['Blueprint'].get('Name')!r}"
    )
    glue.delete_blueprint(Name=name)
    not_found_code, not_found_message = _refusal(lambda: glue.get_blueprint(Name=name))
    assert not_found_code == "EntityNotFoundException", (
        f"expected EntityNotFoundException after delete, got {not_found_code!r}"
    )
    assert not_found_message == "Blueprint with given name not found.", not_found_message


# ===== helpers =====
def _refusal(call):
    """(code, message) of a call that MUST be refused; raises when the call succeeds."""
    try:
        call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be refused but it SUCCEEDED")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_glue_assumable_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-bp-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
