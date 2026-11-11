"""list-experiments-filters-by-experiment-template-id."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-experiments-filters-by-experiment-template-id"
GROUP = "data-plane"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """ListExperiments filtered by experimentTemplateId returns exactly the experiments started
    from that template, excluding experiments started from an unrelated template."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_a = _create_template_retrying(ctx, fis, role_arn, "sim2real-listexp-a-")
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_a))
    template_b = _create_template_retrying(ctx, fis, role_arn, "sim2real-listexp-b-")
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_b))

    exp_a1 = _start_experiment_retrying(ctx, fis, template_a)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, exp_a1))
    exp_a2 = _start_experiment_retrying(ctx, fis, template_a)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, exp_a2))
    exp_b1 = _start_experiment_retrying(ctx, fis, template_b)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, exp_b1))

    seen: list[str] = []
    next_token = None
    while True:
        kwargs = {"experimentTemplateId": template_a}
        if next_token:
            kwargs["nextToken"] = next_token
        page = fis.list_experiments(**kwargs)
        seen.extend(e["id"] for e in page["experiments"])
        next_token = page.get("nextToken")
        if not next_token:
            break

    assert set(seen) == {exp_a1, exp_a2}, f"filtered list mismatch: {set(seen)} != {{exp_a1, exp_a2}}"
    assert exp_b1 not in seen, "unrelated template's experiment leaked into filtered list"
    assert all(e["experimentTemplateId"] == template_a for e in fis.list_experiments(experimentTemplateId=template_a)["experiments"])


# ===== helpers =====
def _create_fis_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-fis-role"},
        ],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role_arn


def _create_template_retrying(ctx, fis, role_arn: str, prefix: str, timeout_s: float = 30.0) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.create_experiment_template(
                clientToken=ctx.unique_name(f"{prefix}tok-"),
                description=ctx.unique_name(prefix),
                stopConditions=[{"source": "none"}],
                targets={},
                actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
                roleArn=role_arn,
                tags={"sim2real:managed": "true", "sim2real:prefix": prefix},
            )["experimentTemplate"]["id"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise last_err


def _start_experiment_retrying(ctx, fis, template_id: str, timeout_s: float = 30.0) -> str:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
