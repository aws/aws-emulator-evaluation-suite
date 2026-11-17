"""start-experiment-cancelled-while-safety-lever-engaged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-cancelled-while-safety-lever-engaged"
GROUP = "safety"
SERVICES = ["fis", "iam", "sts"]

_LEVER_TERMINAL = ("engaged", "disengaged")
_EXPERIMENT_TERMINAL = (
    "completed", "stopped", "cancelled", "failed",
)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _settle_safety_lever(fis, target, reason):
    """Drive the account-global safety lever to ``target`` and return the settled lever.

    AWS refuses an UpdateSafetyLeverState that repeats the current status even with a new
    reason (ConflictException), so a no-op leaves the prior reason in place untouched.
    """
    current = fis.get_safety_lever(id="default")["safetyLever"]
    if current["state"]["status"] == target:
        return current
    fis.update_safety_lever_state(id="default", state={"status": target, "reason": reason})
    deadline = time.monotonic() + 60
    lever = None
    while time.monotonic() < deadline:
        lever = fis.get_safety_lever(id="default")["safetyLever"]
        if lever["state"]["status"] == target:
            return lever
        if lever["state"]["status"] not in _LEVER_TERMINAL and lever["state"]["status"] != "engaging":
            raise AssertionError(f"safety lever left its known states: {lever}")
        time.sleep(2.0)
    raise AssertionError(f"safety lever did not settle to {target!r} with reason {reason!r} (last={lever})")


def _create_fis_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-lever-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Path="/sim2real/")
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_name = "fis-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity")
    )
    return resp["Role"]["Arn"]


def _create_wait_template(ctx, fis, role_arn, *, duration="PT1M"):
    """CreateExperimentTemplate with a minimal, targetless, wait-only body; tracked for cleanup."""
    kwargs = dict(
        clientToken=ctx.unique_name("sim2real-fis-lever-tmpl-"),
        description="sim2real fis safety-lever effect check",
        stopConditions=[{"source": "none"}],
        actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": duration}}},
        targets={},
        roleArn=role_arn,
    )
    # CreateExperimentTemplate stores roleArn without assuming it, so it needs no propagation retry.
    resp = fis.create_experiment_template(**kwargs)
    template_id = resp["experimentTemplate"]["id"]
    ctx.on_cleanup(_teardown(lambda: fis.delete_experiment_template(id=template_id), "ResourceNotFoundException"))
    return template_id


def _start_with_retry(fis, template_id, client_token, role_arn, *, timeout_s=30.0):
    """A freshly created IAM role can take a while to propagate before FIS can assume it;
    retry exactly that documented transient (not a real experiment outcome) rather than surfacing it."""
    transient_message = (
        f"Unable to assume role {role_arn}. Check the trust policy grants access to 'fis.amazonaws.com'"
    )
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(clientToken=client_token, experimentTemplateId=template_id)
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationException" and error.get("Message") == transient_message:
                last_exc = exc
                time.sleep(3)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _poll_experiment_terminal(fis, experiment_id, *, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    experiment = None
    while time.monotonic() < deadline:
        experiment = fis.get_experiment(id=experiment_id)["experiment"]
        if experiment["state"]["status"] in _EXPERIMENT_TERMINAL:
            return experiment
        time.sleep(2.0)
    raise AssertionError(f"experiment {experiment_id} never reached a terminal state (last={experiment})")


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html
@tags(
    "axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes",
    "concern:representation", "dp:api", "plane:control", "plane:data",
    "resource:account-singleton:fis-active-experiment-quota", "timing:real-time",
)
def run(ctx) -> None:
    """Engaging the safety lever settles GetSafetyLever to "engaged" with the given reason; a StartExperiment
    on a wait-only template then still returns 200 but settles to "cancelled" naming the experiment and the
    lever, its wait action never running, while the same call succeeds and completes once disengaged."""
    fis = ctx.client("fis")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    ctx.on_cleanup(lambda: _settle_safety_lever(fis, "disengaged", "sim2real restore to disengaged"))

    # Start from a known baseline in case a previous run left the lever engaged.
    _settle_safety_lever(fis, "disengaged", "sim2real baseline disengage")

    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, fis, role_arn)

    engage_reason = "sim2real safety-lever engaged to block new fis experiments"
    engaged = _settle_safety_lever(fis, "engaged", engage_reason)
    assert engaged["state"]["status"] == "engaged", engaged
    assert engaged["state"]["reason"] == engage_reason, engaged["state"]

    # StartExperiment itself is accepted (no ClientError) while the lever is engaged...
    blocked_start = _start_with_retry(fis, template_id, ctx.unique_name("sim2real-start-engaged-"), role_arn)
    blocked_id = blocked_start["experiment"]["id"]

    # ...but the lever prevents the experiment from ever running: it settles to "cancelled" with
    # a message naming this experiment and the lever's own arn, and its action never executes.
    blocked = _poll_experiment_terminal(fis, blocked_id)
    assert blocked["state"]["status"] == "cancelled", blocked["state"]
    expected_cancel_reason = (
        f"Experiment {blocked_id} has been cancelled by the safety lever "
        f"'arn:aws:fis:{ctx.region}:{account_id}:safety-lever/default'."
    )
    assert blocked["state"]["reason"] == expected_cancel_reason, blocked["state"]
    assert blocked["actions"]["waitAction"]["state"]["status"] == "cancelled", blocked["actions"]

    # Disengaging settles GetSafetyLever back, with its own stored reason.
    disengage_reason = "sim2real safety-lever disengaged to resume fis experiments"
    disengaged = _settle_safety_lever(fis, "disengaged", disengage_reason)
    assert disengaged["state"]["status"] == "disengaged", disengaged
    assert disengaged["state"]["reason"] == disengage_reason, disengaged["state"]

    # The positive control: the same template's StartExperiment now actually runs to completion.
    allowed_start = _start_with_retry(fis, template_id, ctx.unique_name("sim2real-start-disengaged-"), role_arn)
    allowed_id = allowed_start["experiment"]["id"]
    allowed = _poll_experiment_terminal(fis, allowed_id)
    assert allowed["state"]["status"] == "completed", allowed["state"]
    assert allowed["actions"]["waitAction"]["state"]["status"] == "completed", allowed["actions"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
