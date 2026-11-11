"""stop-experiment-transitions-running-to-stopped."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-experiment-transitions-running-to-stopped"
GROUP = "state-machine"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """StopExperiment on a running experiment deterministically transitions running->stopping->stopped."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, duration="PT5M")

    resp = _start_with_retry(ctx, fis, template_id)
    experiment_id = resp["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))

    _poll_until(
        lambda: fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"],
        lambda s: s == "running",
        timeout_s=90,
        interval_s=3,
    )

    stop_resp = fis.stop_experiment(id=experiment_id)
    stop_status = stop_resp["experiment"]["state"]["status"]
    assert stop_status in ("stopping", "stopped"), stop_status

    final_status = _poll_until(
        lambda: fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"],
        lambda s: s in ("stopped", "failed", "cancelled", "completed"),
        timeout_s=60,
        interval_s=3,
    )
    assert final_status == "stopped", final_status


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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
        Tags=[{"Key": "sim2real", "Value": "fis-state-machine"}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

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
    ctx.on_cleanup(_cleanup_role)
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
        tags={"sim2real": "fis-state-machine"},
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
        code = e.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        # StopExperiment refuses an experiment that already ended; anything else is a real failure.
        if code != "ValidationException":
            raise
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
