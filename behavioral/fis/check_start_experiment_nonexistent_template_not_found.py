"""start-experiment-nonexistent-template-not-found."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-nonexistent-template-not-found"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """StartExperiment against a non-existent experiment template id raises
    ResourceNotFoundException, creates no orphaned experiment, while starting an
    experiment from a real template still succeeds."""
    fis = ctx.client("fis")

    bogus_template_id = "nonexistent" + uuid.uuid4().hex[:16]
    code, message = _error(
        lambda: fis.start_experiment(
            clientToken=ctx.unique_name("sim2real-fis-tok-"),
            experimentTemplateId=bogus_template_id,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "ExperimentTemplate not found.", f"expected 'ExperimentTemplate not found.', got {message!r}"

    listed = fis.list_experiments(experimentTemplateId=bogus_template_id)
    assert listed["experiments"] == [], "no experiment should exist for a template id that never existed"

    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn)
    real_experiment_id = _start_experiment(ctx, template_id)

    fetched = fis.get_experiment(id=real_experiment_id)["experiment"]
    assert fetched["experimentTemplateId"] == template_id, (
        f"expected experiment {real_experiment_id} to reference template {template_id}, "
        f"got {fetched['experimentTemplateId']}"
    )
    assert fetched["state"]["status"] in (
        "pending",
        "initiating",
        "running",
        "completed",
    ), fetched["state"]


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


def _create_fis_role(ctx) -> str:
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return resp["Role"]["Arn"]


def _retry_transient(fn, tries: int = 8, delay_s: float = 5.0):
    """Retry setup calls past IAM role propagation lag (freshly created roles are not
    immediately visible/assumable to other services)."""
    last_exc: Exception | None = None
    for _ in range(tries):
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = str(e)
            if code in ("ResourceNotFoundException", "AccessDeniedException") or (
                code == "ValidationException" and "assume role" in msg.lower()
            ):
                last_exc = e
                time.sleep(delay_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited without a stored exception to raise"
    raise last_exc


def _create_wait_template(ctx, role_arn: str, experiment_options: dict[str, Any] | None = None) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = dict(
        clientToken=ctx.unique_name("sim2real-fis-tmpl-tok-"),
        description="sim2real behavioral wait template",
        stopConditions=[{"source": "none"}],
        actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        targets={},
        roleArn=role_arn,
        tags={"sim2real:managed": "true"},
    )
    if experiment_options:
        kwargs["experimentOptions"] = experiment_options
    resp = _retry_transient(lambda: fis.create_experiment_template(**kwargs))
    template_id = resp["experimentTemplate"]["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


def _start_experiment(ctx, template_id: str) -> str:
    fis = ctx.client("fis")
    resp = _retry_transient(
        lambda: fis.start_experiment(
            clientToken=ctx.unique_name("sim2real-fis-exp-tok-"),
            experimentTemplateId=template_id,
            tags={"sim2real:managed": "true"},
        )
    )
    experiment_id = resp["experiment"]["id"]

    def _cleanup() -> None:
        try:
            status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
            if status in ("pending", "initiating", "running"):
                fis.stop_experiment(id=experiment_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            # an experiment already in a final state rejects StopExperiment; it needs no stop
            status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
            if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
                raise

    ctx.on_cleanup(_cleanup)
    return experiment_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
