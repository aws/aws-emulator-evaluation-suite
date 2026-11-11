"""list-experiments-malformed-filter-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "list-experiments-malformed-filter-rejected"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """ListExperiments with an experimentTemplateId filter over the 64-character limit is rejected
    with ValidationException rather than ignored, while an unfiltered call still succeeds."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)
    template_id = _create_template_retrying(ctx, fis, role_arn)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))

    experiment_id = _start_experiment_retrying(ctx, fis, template_id)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, experiment_id))

    # Positive control: the operation works and finds the experiment we started. Bounded
    # retry, not a bare read, because ListExperiments can lag start_experiment briefly.
    found = _poll_until_listed(fis, template_id, experiment_id)
    assert experiment_id in found, f"expected {experiment_id!r} in {found!r} after polling"

    malformed_filter = "x" * 65  # exceeds the 64-char max length constraint on experimentTemplateId
    code, message = _error(lambda: fis.list_experiments(experimentTemplateId=malformed_filter))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "Maximum length exceeded: experimentTemplateId"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _create_fis_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-fis-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "fis.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
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
                description=ctx.unique_name("sim2real-err-fis-"),
                stopConditions=[{"source": "none"}],
                targets={},
                actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
                roleArn=role_arn,
                tags={"sim2real:managed": "true"},
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


def _poll_until_listed(fis, template_id: str, experiment_id: str, timeout_s: float = 30.0) -> list:
    """Poll ListExperiments(experimentTemplateId=) until it lists experiment_id or the
    deadline passes; returns the last-seen id list either way for the caller to assert on."""
    deadline = time.monotonic() + timeout_s
    ids: list = []
    while time.monotonic() < deadline:
        ids = [e["id"] for e in fis.list_experiments(experimentTemplateId=template_id)["experiments"]]
        if experiment_id in ids:
            return ids
        time.sleep(2)
    return ids


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
