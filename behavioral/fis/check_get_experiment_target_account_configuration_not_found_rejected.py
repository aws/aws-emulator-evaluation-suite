"""get-experiment-target-account-configuration-not-found-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-experiment-target-account-configuration-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """GetExperimentTargetAccountConfiguration and the template-level GetTargetAccountConfiguration
    each fail with ResourceNotFoundException and their exact messages for a never-configured account,
    while the account configured on the template resolves at the experiment level with its roleArn."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_wait_template(ctx, role_arn, experiment_options={"accountTargeting": "multi-account"})

    # Documentation placeholder account ids, so no real account is named.
    configured_account = "111122223333"
    target_role = f"arn:aws:iam::{configured_account}:role/sim2real-fis-target-snapshot"
    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=configured_account,
        roleArn=target_role,
        description="snapshot-target",
    )
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(
            experimentTemplateId=template_id, accountId=configured_account
        )
    )

    experiment_id = _start_experiment(ctx, template_id)

    snapshot = _poll_until_experiment_target_account(ctx, experiment_id, configured_account)
    assert snapshot["accountId"] == configured_account, (
        f"expected accountId {configured_account}, got {snapshot['accountId']}"
    )
    assert snapshot["roleArn"] == target_role, f"expected roleArn {target_role}, got {snapshot['roleArn']}"

    never_configured_account = "444455556666"
    code, message = _error(
        lambda: fis.get_experiment_target_account_configuration(
            experimentId=experiment_id, accountId=never_configured_account
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = (
        f"TargetAccountConfiguration for experiment {experiment_id} and target account "
        f"{never_configured_account} not found"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    template_level_code, template_level_message = _error(
        lambda: fis.get_target_account_configuration(
            experimentTemplateId=template_id, accountId=never_configured_account
        )
    )
    assert template_level_code == "ResourceNotFoundException", (
        f"template-level lookup should independently 404, got {template_level_code}"
    )
    expected_template_level = "TargetAccountConfiguration not found."
    assert template_level_message == expected_template_level, (
        f"expected template-level message {expected_template_level!r}, got {template_level_message!r}"
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
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
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
    assert last_exc is not None
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
            # An experiment that reached a final state after the read above rejects StopExperiment
            # with this ValidationException; it needs no stop.
            if e.response["Error"]["Code"] == "ValidationException" and e.response["Error"].get(
                    "Message", "").startswith("Cannot modify the state of an experiment in final state"):
                return
            status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
            if status not in ("stopping", "stopped", "completed", "failed", "cancelled"):
                raise

    ctx.on_cleanup(_cleanup)
    return experiment_id


def _poll_until_experiment_target_account(
    ctx, experiment_id: str, account_id: str, timeout_s: float = 30.0, interval_s: float = 2.0
) -> dict[str, Any]:
    fis = ctx.client("fis")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fis.get_experiment_target_account_configuration(
                experimentId=experiment_id, accountId=account_id
            )["targetAccountConfiguration"]
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(
        f"target account configuration for {account_id} never appeared on experiment {experiment_id}: {last_exc}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
