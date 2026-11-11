"""experiment-tags-round-trip-through-start."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "experiment-tags-round-trip-through-start"
GROUP = "representation"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Tags supplied to StartExperiment round-trip byte-exact via GetExperiment, including
    keys/values with special characters."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_id = _create_template_retrying(ctx, fis, role_arn)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))

    tags = {
        "plain-key": "plain-value",
        "unicode-key": "ünïcode-测试-value",
        "empty-value-key": "",
        "spaced key": "value with spaces  and  double  gaps",
    }

    experiment_id = _start_experiment_retrying(ctx, fis, template_id, tags)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))

    got = fis.get_experiment(id=experiment_id)["experiment"]
    assert got["tags"] == tags, f"tags did not round-trip exactly: {got['tags']!r} != {tags!r}"


# ===== helpers =====
def _create_fis_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role_arn


def _create_template_retrying(ctx, fis, role_arn: str, timeout_s: float = 30.0) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.create_experiment_template(
                clientToken=ctx.unique_name("sim2real-fis-tmpl-"),
                description=ctx.unique_name("sim2real-repr-fis-"),
                stopConditions=[{"source": "none"}],
                targets={},
                actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
                roleArn=role_arn,
            )["experimentTemplate"]["id"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = err
            time.sleep(2)
    raise last_err


def _start_experiment_retrying(ctx, fis, template_id: str, tags: dict, timeout_s: float = 30.0) -> str:
    """StartExperiment assumes the template's roleArn immediately; a role created
    moments earlier in the same check can still be outside IAM's eventual-consistency
    propagation window, so retry only on that specific transient rejection."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-start-"),
                experimentTemplateId=template_id,
                tags=tags,
            )["experiment"]["id"]
        except ClientError as err:
            if "Unable to assume role" not in str(err):
                raise
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
