"""experiment-tags-unicode-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "experiment-tags-unicode-preserved"
GROUP = "representation"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Unicode tag keys/values (emoji, CJK, Cyrillic, accented Latin) supplied on
    StartExperiment come back byte-identical (no normalization/mojibake/truncation)
    from both the StartExperiment response and a subsequent GetExperiment."""
    fis = ctx.client("fis")
    role_arn = _create_orchestrator_role(ctx)
    template_id = _create_wait_template(ctx, role_arn)

    tags = {
        "cjk-\u4e16\u754c": "\u4f60\u597d-\u4e16\u754c",
        "cyrillic-\u041f\u0440\u0438\u0432\u0435\u0442": "\u041c\u0438\u0440-1234",
        "accented-caf\u00e9-na\u00efve": "fa\u00e7ade-Z\u00fcrich",
        "arabic-\u0645\u0631\u062d\u0628\u0627": "\u0627\u0644\u0639\u0627\u0644\u0645",
    }

    started = _start_experiment_with_retry(
        ctx,
        fis,
        clientToken=ctx.unique_name("sim2real-fis-exp-"),
        experimentTemplateId=template_id,
        tags=tags,
    )
    experiment_id = started["id"]
    ctx.on_cleanup(lambda: _stop_ignore_terminal(fis, experiment_id))

    assert started["tags"] == tags, (
        f"StartExperiment response tags mismatch: expected {tags!r}, got {started['tags']!r}"
    )

    got = fis.get_experiment(id=experiment_id)["experiment"]
    assert got["tags"] == tags, (
        f"GetExperiment tags mismatch: expected {tags!r}, got {got['tags']!r}"
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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
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


def _start_experiment_with_retry(ctx, fis, **kwargs) -> dict:
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
