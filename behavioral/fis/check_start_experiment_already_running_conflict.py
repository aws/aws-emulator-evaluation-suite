"""start-experiment-already-running-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-experiment-already-running-conflict"
GROUP = "state-machine"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Reusing a StartExperiment clientToken with the SAME template returns the SAME experiment,
    while reusing it with a DIFFERENT template is a parameter mismatch rejected with
    ConflictException."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, duration="PT4M")
    template_id2 = _create_wait_template(ctx, role_arn, duration="PT4M")

    shared_token = ctx.unique_name("shared-token-")
    first = _start_with_retry(ctx, fis, template_id, client_token=shared_token)
    experiment_id = first["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))

    # idempotent replay: identical clientToken + identical experimentTemplateId returns the same experiment,
    # not a second run
    replay = fis.start_experiment(clientToken=shared_token, experimentTemplateId=template_id)
    assert replay["experiment"]["id"] == experiment_id, replay["experiment"]["id"]

    active = [
        e for e in fis.list_experiments(experimentTemplateId=template_id)["experiments"]
        if e["state"]["status"] in ("pending", "initiating", "running")
    ]
    assert len(active) == 1, active
    assert active[0]["id"] == experiment_id

    # true conflict: the same clientToken reused with a DIFFERENT experimentTemplateId is a parameter
    # mismatch within the idempotency window -> ConflictException
    code, message = _error(lambda: fis.start_experiment(
        clientToken=shared_token, experimentTemplateId=template_id2
    ))
    assert code == "ConflictException", code
    expected = f"clientToken {shared_token} is not assigned to this resource."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no experiment was created against the second template via the conflicting token
    existing2 = fis.list_experiments(experimentTemplateId=template_id2)["experiments"]
    assert existing2 == [], existing2


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


def _start_with_retry(ctx, fis, template_id, *, timeout_s=60.0, client_token=None):
    """A freshly created IAM role can take a while to propagate before FIS can assume it;
    retry the role-assume failure (not a real experiment outcome) rather than surfacing it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        token = client_token or ctx.unique_name("start-")
        try:
            return fis.start_experiment(clientToken=token, experimentTemplateId=template_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in msg.lower():
                last_err = e
                time.sleep(2)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
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
