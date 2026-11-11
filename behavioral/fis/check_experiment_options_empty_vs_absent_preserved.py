"""experiment-options-empty-vs-absent-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "experiment-options-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c3", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Omitting experimentOptions.actionsMode yields a server-defaulted value on StartExperiment and
    GetExperiment, while an explicit "skip-all" is preserved verbatim, not normalized back to the
    default."""
    fis = ctx.client("fis")
    role_arn = _create_orchestrator_role(ctx)
    template_id = _create_wait_template(ctx, role_arn)

    # Run A: experimentOptions omitted entirely -> server applies its own default.
    started_a = _start_experiment_with_retry(
        ctx,
        fis,
        clientToken=ctx.unique_name("sim2real-fis-exp-a-"),
        experimentTemplateId=template_id,
    )
    experiment_a_id = started_a["id"]
    ctx.on_cleanup(lambda: _stop_ignore_terminal(fis, experiment_a_id))

    default_mode = started_a.get("experimentOptions", {}).get("actionsMode")
    assert default_mode == "run-all", f"unexpected default actionsMode: {default_mode!r}"
    got_a = fis.get_experiment(id=experiment_a_id)["experiment"]
    got_a_mode = got_a["experimentOptions"]["actionsMode"]
    assert got_a_mode == "run-all", (
        f"GetExperiment did not preserve the server-defaulted actionsMode: expected 'run-all', got {got_a_mode!r}"
    )

    # Run B: experimentOptions.actionsMode explicitly supplied with a *different*
    # value than the default -> the explicit value must be honored, not silently
    # coerced back to the server default from run A.
    started_b = _start_experiment_with_retry(
        ctx,
        fis,
        clientToken=ctx.unique_name("sim2real-fis-exp-b-"),
        experimentTemplateId=template_id,
        experimentOptions={"actionsMode": "skip-all"},
    )
    experiment_b_id = started_b["id"]
    ctx.on_cleanup(lambda: _stop_ignore_terminal(fis, experiment_b_id))

    started_b_mode = started_b["experimentOptions"]["actionsMode"]
    assert started_b_mode == "skip-all", (
        f"StartExperiment did not honor the explicit actionsMode override: expected 'skip-all', got {started_b_mode!r}"
    )
    got_b = fis.get_experiment(id=experiment_b_id)["experiment"]
    got_b_mode = got_b["experimentOptions"]["actionsMode"]
    assert got_b_mode == "skip-all", (
        f"GetExperiment did not preserve the explicit actionsMode override: expected 'skip-all', got {got_b_mode!r}"
    )


# ===== helpers =====


def _stop_ignore_terminal(fis, experiment_id: str) -> None:
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


def _create_orchestrator_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_wait_template(
    ctx, role_arn: str, experiment_options: dict[str, Any] | None = None
) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = dict(
        clientToken=ctx.unique_name("sim2real-fis-tmpl-"),
        description="sim2real fis behavioral check template",
        stopConditions=[{"source": "none"}],
        actions={
            "wait1": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}
        },
        targets={},
        roleArn=role_arn,
        tags={"suite": "sim2real"},
    )
    if experiment_options:
        kwargs["experimentOptions"] = experiment_options

    # A freshly created IAM role can take a few seconds to propagate before FIS can
    # resolve/assume it (IAM's documented eventual-consistency window for a new
    # role). Poll CreateExperimentTemplate until the role is recognized.
    deadline = time.monotonic() + 30
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            template_id = fis.create_experiment_template(**kwargs)["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
            return template_id
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            if code != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise AssertionError(f"role never became usable by FIS: {last_err}")


def _start_experiment_with_retry(ctx, fis, **kwargs: Any) -> dict[str, Any]:
    """StartExperiment assumes the template's roleArn immediately; a role created
    moments earlier in the same check can still be outside IAM's eventual-consistency
    propagation window, so retry on the transient "Unable to assume role" rejection."""
    deadline = time.monotonic() + 60
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(**kwargs)["experiment"]
        except Exception as err:  # noqa: BLE001
            message = str(err)
            if "Unable to assume role" not in message:
                raise
            last_err = err
            time.sleep(3)
    raise AssertionError(f"role never became assumable by FIS: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
