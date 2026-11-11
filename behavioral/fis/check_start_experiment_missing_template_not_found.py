"""start-experiment-missing-template-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-missing-template-not-found"
GROUP = "error-semantics"
SERVICES = ["fis"]

_TEMPLATE_NOT_FOUND = "ExperimentTemplate not found."


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """StartExperiment against a deleted experiment template returns ResourceNotFoundException before any state is created."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)

    template_id = _create_wait_template(ctx, role_arn, duration="PT1M")
    fis.delete_experiment_template(id=template_id)

    # independent read: the deleted template itself is gone, not just unusable
    get_code, get_message = _error(lambda: fis.get_experiment_template(id=template_id))
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {get_code}"
    assert get_message == _TEMPLATE_NOT_FOUND, f"expected message {_TEMPLATE_NOT_FOUND!r}, got {get_message!r}"

    code, message = _error(lambda: fis.start_experiment(
        clientToken=ctx.unique_name("start-"), experimentTemplateId=template_id
    ))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == _TEMPLATE_NOT_FOUND, f"expected message {_TEMPLATE_NOT_FOUND!r}, got {message!r}"

    # effect absent: no experiment was created against the deleted template
    existing = fis.list_experiments(experimentTemplateId=template_id)["experiments"]
    assert existing == [], existing

    # positive control: a fresh, still-existing template can genuinely be started
    template_id2 = _create_wait_template(ctx, role_arn, duration="PT1M")
    resp = _start_with_retry(ctx, fis, template_id2)
    experiment_id = resp["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))
    status = resp["experiment"]["state"]["status"]
    assert status in ("pending", "initiating", "running"), f"expected an active status, got {status}"


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


def _start_with_retry(ctx, fis, template_id, *, timeout_s=60.0):
    """A freshly created IAM role can take a while to propagate before FIS can assume it;
    retry the role-assume failure (not a real experiment outcome) rather than surfacing it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(clientToken=ctx.unique_name("start-"), experimentTemplateId=template_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in msg.lower():
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _create_fis_role(ctx, policy_statements=None):
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "fis.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "fis-behavioral"}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    if policy_statements:
        policy_name = ctx.unique_name("sim2real-fis-policy-")
        doc = {"Version": "2012-10-17", "Statement": policy_statements}
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))

        def _cleanup_policy():
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

        ctx.on_cleanup(_cleanup_policy)
    return role_arn


def _delete_template_safe(ctx, template_id):
    fis = ctx.client("fis")
    try:
        fis.delete_experiment_template(id=template_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_wait_template(ctx, role_arn, *, duration="PT1M", account_targeting=None):
    fis = ctx.client("fis")
    kwargs = dict(
        clientToken=ctx.unique_name("tmpl-"),
        description="sim2real fis behavioral check (wait action)",
        stopConditions=[{"source": "none"}],
        actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": duration}}},
        targets={},
        roleArn=role_arn,
        tags={"sim2real": "fis-behavioral"},
    )
    if account_targeting:
        kwargs["experimentOptions"] = {"accountTargeting": account_targeting}

    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = fis.create_experiment_template(**kwargs)
            template_id = resp["experimentTemplate"]["id"]
            ctx.on_cleanup(lambda: _delete_template_safe(ctx, template_id))
            return template_id
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ValidationException", "ResourceNotFoundException"):
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _safe_stop(ctx, experiment_id):
    fis = ctx.client("fis")
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
