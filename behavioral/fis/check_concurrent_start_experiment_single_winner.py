"""concurrent-start-experiment-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-start-experiment-single-winner"
GROUP = "concurrency"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Two simultaneous StartExperiment calls with the SAME clientToken never create two experiments:
    both racers get the identical idempotent reply, or the loser is rejected with ConflictException
    while the winner commits."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, duration="PT3M")
    shared_token = ctx.unique_name("race-token-")

    def _attempt():
        deadline = time.monotonic() + 60
        while True:
            try:
                resp = fis.start_experiment(clientToken=shared_token, experimentTemplateId=template_id)
                return ("ok", resp["experiment"]["id"])
            except ClientError as e:
                code = e.response["Error"]["Code"]
                msg = e.response["Error"].get("Message", "")
                # a freshly created IAM role can take a while to propagate; retry the role-assume
                # failure (not a real outcome) so both racers contend once the role is actually usable
                if code == "ValidationException" and "assume role" in msg.lower() and time.monotonic() < deadline:
                    time.sleep(2)
                    continue
                return ("error", code, msg)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [f.result() for f in [pool.submit(_attempt) for _ in range(2)]]

    oks = [r for r in results if r[0] == "ok"]
    errors = [r for r in results if r[0] == "error"]
    # a race on the same clientToken either resolves to two idempotent replies carrying the identical
    # experiment id, or the idempotency store itself rejects the losing racer with ConflictException
    # while it is still committing the winner — either way, exactly one experiment is ever created and
    # no other error code is acceptable
    assert len(oks) in (1, 2), results
    if errors:
        assert len(errors) == 1, results
        assert errors[0][1] == "ConflictException", errors[0][1]
        expected = "An operation is currently in progress with the same clientToken. Please try again."
        assert errors[0][2] == expected, errors[0][2]
    if len(oks) == 2:
        ids = {r[1] for r in oks}
        assert len(ids) == 1, results

    experiment_id = oks[0][1]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))

    active = [
        e for e in fis.list_experiments(experimentTemplateId=template_id)["experiments"]
        if e["state"]["status"] in ("pending", "initiating", "running")
    ]
    assert len(active) == 1, active
    assert active[0]["id"] == experiment_id, (active[0]["id"], experiment_id)


# ===== helpers =====

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
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-fis-role"},
        ],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

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
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-fis-tmpl"},
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
