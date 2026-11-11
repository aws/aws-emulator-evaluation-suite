"""start-experiment-insufficient-role-permissions-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-insufficient-role-permissions-denied"
GROUP = "overly-permissive"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """An experiment template whose designated execution role does NOT trust fis.amazonaws.com (i.e. FIS
    itself cannot assume it) must have StartExperiment rejected rather than silently accepted and left to
    fail later during background execution — proving FIS validates the role's usability up front."""
    fis = ctx.client("fis")
    iam = ctx.client("iam")

    # a role that trusts a different service, NOT fis.amazonaws.com -> FIS can never assume it
    untrusted_role_name = ctx.unique_name("sim2real-fis-untrusted-")
    untrusted_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    untrusted_resp = iam.create_role(
        RoleName=untrusted_role_name,
        AssumeRolePolicyDocument=json.dumps(untrusted_trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    untrusted_role_arn = untrusted_resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, untrusted_role_name))

    template_id = _create_wait_template(ctx, untrusted_role_arn, duration="PT1M")

    expected_msg = (
        f"Unable to assume role {untrusted_role_arn}. "
        "Check the trust policy grants access to 'fis.amazonaws.com'"
    )
    denied_code = None
    denied_msg = None
    leaked_experiment_id = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            resp = fis.start_experiment(clientToken=ctx.unique_name("denied-"), experimentTemplateId=template_id)
            denied_code = None
            leaked_experiment_id = resp["experiment"]["id"]
            break
        except ClientError as e:
            denied_code = e.response["Error"]["Code"]
            denied_msg = e.response["Error"].get("Message")
            if denied_code == "ValidationException" and denied_msg != expected_msg:
                # transient IAM propagation of the just-created role; retry
                time.sleep(3)
                continue
            break

    if leaked_experiment_id is not None:
        # an over-permissive target may have actually started this; do not leave it running
        ctx.on_cleanup(lambda: _safe_stop(ctx, leaked_experiment_id))

    assert denied_code == "ValidationException", (
        f"expected ValidationException for the untrusted role, got code={denied_code!r} "
        f"message={denied_msg!r}"
    )
    assert denied_msg == expected_msg, f"expected message {expected_msg!r}, got {denied_msg!r}"

    # effect absent: no experiment was created against the untrusted-role template
    active = fis.list_experiments(experimentTemplateId=template_id)["experiments"]
    assert active == [], active

    # positive control: the same wait-action shape with a properly-trusted role genuinely starts,
    # confirmed via an independent read (get_experiment), not the mutating call's own response
    role_arn = _create_fis_role(ctx)
    template_id2 = _create_wait_template(ctx, role_arn, duration="PT1M")
    control = _start_with_retry(ctx, fis, template_id2)
    experiment_id = control["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))
    control_detail = fis.get_experiment(id=experiment_id)["experiment"]
    assert control_detail["state"]["status"] in ("pending", "initiating", "running"), (
        f"expected the properly-trusted-role experiment to be underway, got status="
        f"{control_detail['state']['status']!r}"
    )


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


# ===== helpers =====

def _delete_role_safe(ctx, role_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_policy_safe(ctx, role_name, policy_name):
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_fis_role(ctx, policy_statements=None):
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_safe(ctx, role_name))
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
        tags={"sim2real-check": CHECK},
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
