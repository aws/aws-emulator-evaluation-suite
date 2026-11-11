"""e2e-experiment-create-start-observe-stop-teardown."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-experiment-create-start-observe-stop-teardown"
GROUP = "e2e"
SERVICES = ["fis"]

_TEMPLATE_NOT_FOUND = "ExperimentTemplate not found."


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Full lifecycle: create template w/ a real target, start, observe resolved targets and
    running state, stop, delete template -- assert the consequence chain, not status codes."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    # Execution role: FIS assumes this to run the experiment; needs permission to invoke the
    # aws:fis:inject-api-internal-error action.
    exec_role_arn = _create_role(
        ctx,
        iam,
        trust_service="fis.amazonaws.com",
        inline_actions=["fis:InjectApiInternalError"],
    )
    # Target role: the resource the action's "aws:iam:role" target points at. Its own trust
    # policy is irrelevant here -- it is never assumed by us, only referenced by ARN.
    target_role_arn = _create_role(ctx, iam, trust_service="ec2.amazonaws.com", inline_actions=None)

    action_targets = fis.get_action(id="aws:fis:inject-api-internal-error")["action"]["targets"]
    target_key = next(iter(action_targets))

    description = ctx.unique_name("sim2real-e2e-fis-")
    template = _create_template_retrying(
        ctx,
        fis,
        description=description,
        role_arn=exec_role_arn,
        targets={
            "roleTarget": {
                "resourceType": "aws:iam:role",
                "resourceArns": [target_role_arn],
                "selectionMode": "ALL",
            }
        },
        actions={
            "injectAction": {
                "actionId": "aws:fis:inject-api-internal-error",
                "parameters": {"duration": "PT1M", "service": "ec2", "percentage": "10", "operations": "DescribeRegions"},
                "targets": {target_key: "roleTarget"},
            }
        },
    )
    template_id = template["id"]
    ctx.on_cleanup(lambda: _delete_template_quiet(fis, template_id))

    experiment_id = _start_experiment_retrying(ctx, fis, template_id)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))

    status = _poll_experiment_status(fis, experiment_id, {"running", "completed", "failed"}, timeout_s=60)
    assert status in ("running", "completed"), f"experiment did not progress (status={status!r})"

    resolved = fis.list_experiment_resolved_targets(experimentId=experiment_id)["resolvedTargets"]
    assert len(resolved) == 1, f"expected exactly 1 resolved target, got {resolved}"
    assert resolved[0]["resourceType"] == "aws:iam:role", (
        f"expected resolved target type aws:iam:role, got {resolved[0]['resourceType']!r}"
    )
    # targetInformation is a generic string->string map (key name is not contractually fixed);
    # assert the real consequence -- our target role ARN is present as one of the values.
    assert target_role_arn in resolved[0]["targetInformation"].values(), (
        f"resolved target does not reference our role: {resolved[0]['targetInformation']!r}"
    )

    fis.stop_experiment(id=experiment_id)
    stopped_status = _poll_experiment_status(fis, experiment_id, {"stopped", "completed", "failed"}, timeout_s=60)
    assert stopped_status in ("stopped", "completed"), f"expected stopped/completed, got {stopped_status!r}"

    fis.delete_experiment_template(id=template_id)
    code, message = _error(lambda: fis.get_experiment_template(id=template_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == _TEMPLATE_NOT_FOUND, f"expected message {_TEMPLATE_NOT_FOUND!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises AssertionError: a target accepting a call real AWS refuses must never be mistaken
    for a falsy code."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _create_role(ctx, iam, trust_service: str, inline_actions):
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:check", "Value": CHECK},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if inline_actions:
        policy_name = f"{name}-policy"
        policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": inline_actions, "Resource": "*"}]}
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return role_arn


def _create_template_retrying(ctx, fis, description, role_arn, targets, actions, timeout_s: float = 30.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.create_experiment_template(
                clientToken=ctx.unique_name("sim2real-fis-tmpl-"),
                description=description,
                stopConditions=[{"source": "none"}],
                targets=targets,
                actions=actions,
                roleArn=role_arn,
                tags={"sim2real-check": CHECK},
            )["experimentTemplate"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise last_err


def _delete_template_quiet(fis, template_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _start_experiment_retrying(ctx, fis, template_id: str, timeout_s: float = 30.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-start-"), experimentTemplateId=template_id
            )["experiment"]["id"]
        except ClientError as err:
            last_err = err
            time.sleep(2)
    raise last_err


def _stop_experiment_quiet(fis, experiment_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


def _poll_experiment_status(fis, experiment_id: str, stop_on: set, timeout_s: float = 90.0, interval_s: float = 1.5):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        last_status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if last_status in stop_on:
            return last_status
        time.sleep(interval_s)
    raise AssertionError(
        f"experiment {experiment_id} did not reach {stop_on} within {timeout_s}s (last status={last_status!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
