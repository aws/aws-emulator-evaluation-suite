"""delete-target-account-configuration-running-experiment-isolated."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-target-account-configuration-running-experiment-isolated"
GROUP = "error-semantics"
SERVICES = ["fis"]

FAKE_TARGET_ACCOUNT_ID = "111122223333"
_TAC_NOT_FOUND = "TargetAccountConfiguration not found."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """Per AWS FIS docs, deleting a template's target account configuration does not affect a currently
    running experiment: the experiment's own snapshot (GetExperimentTargetAccountConfiguration) survives
    the template-level delete unchanged, so the running experiment's target is never orphaned."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, duration="PT4M", account_targeting="multi-account")

    target_role_arn = f"arn:aws:iam::{FAKE_TARGET_ACCOUNT_ID}:role/{ctx.unique_name('sim2real-fis-target-')}"
    fis.create_target_account_configuration(
        clientToken=ctx.unique_name("tac-"),
        experimentTemplateId=template_id,
        accountId=FAKE_TARGET_ACCOUNT_ID,
        roleArn=target_role_arn,
        description="isolation check",
    )

    resp = _start_with_retry(ctx, fis, template_id)
    experiment_id = resp["experiment"]["id"]
    ctx.on_cleanup(lambda: _safe_stop(ctx, experiment_id))

    _poll_until(
        lambda: fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"],
        # the fake target account can never actually be assumed, so the experiment may end up
        # "failed" during execution — what matters here is that it left "pending"/"initiating"
        # and the per-experiment target-account snapshot was captured
        lambda s: s in ("running", "completed", "failed", "stopped"),
        timeout_s=90,
        interval_s=3,
    )

    snapshot_before = fis.get_experiment_target_account_configuration(
        experimentId=experiment_id, accountId=FAKE_TARGET_ACCOUNT_ID
    )["targetAccountConfiguration"]
    assert snapshot_before["roleArn"] == target_role_arn, (
        f"expected experiment snapshot roleArn {target_role_arn!r} before delete, "
        f"got {snapshot_before['roleArn']!r}"
    )

    # deleting the template-level configuration must succeed even while an experiment using it is running
    fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=FAKE_TARGET_ACCOUNT_ID)

    # the template-level configuration is now gone
    code, message = _error(lambda: fis.get_target_account_configuration(
        experimentTemplateId=template_id, accountId=FAKE_TARGET_ACCOUNT_ID
    ))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException from Get, got {code!r}"
    assert message == _TAC_NOT_FOUND, f"expected message {_TAC_NOT_FOUND!r} from Get, got {message!r}"

    # a mutation on the now-dead template-level configuration must also fail not-found, not upsert one
    update_code, update_message = _error(lambda: fis.update_target_account_configuration(
        experimentTemplateId=template_id, accountId=FAKE_TARGET_ACCOUNT_ID, roleArn=target_role_arn
    ))
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Update on deleted config, got {update_code!r}"
    )
    assert update_message == _TAC_NOT_FOUND, (
        f"expected message {_TAC_NOT_FOUND!r} from Update on deleted config, got {update_message!r}"
    )

    # isolation invariant: the already-running experiment's own snapshot is untouched
    snapshot_after = fis.get_experiment_target_account_configuration(
        experimentId=experiment_id, accountId=FAKE_TARGET_ACCOUNT_ID
    )["targetAccountConfiguration"]
    assert snapshot_after["roleArn"] == target_role_arn, (
        f"expected experiment snapshot roleArn {target_role_arn!r} to survive template-level delete, "
        f"got {snapshot_after['roleArn']!r}"
    )
    assert snapshot_after["accountId"] == FAKE_TARGET_ACCOUNT_ID, (
        f"expected experiment snapshot accountId {FAKE_TARGET_ACCOUNT_ID!r}, got {snapshot_after['accountId']!r}"
    )


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
