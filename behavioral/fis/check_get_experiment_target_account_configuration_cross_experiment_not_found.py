"""get-experiment-target-account-configuration-cross-experiment-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-experiment-target-account-configuration-cross-experiment-not-found"
GROUP = "error-semantics"
SERVICES = ["fis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """GetExperimentTargetAccountConfiguration is scoped per-experiment: an accountId valid for
    experiment A's configuration is ResourceNotFoundException against unrelated experiment B,
    while the identical lookup against A (the positive control) succeeds."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")

    role_arn = _create_fis_role(ctx, iam)

    template_a = _create_template_retrying(ctx, fis, role_arn, "sim2real-xexp-a-", multi_account=True)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_a))
    account_id = "111122223333"
    target_role_arn = f"arn:aws:iam::{account_id}:role/sim2real-target-role"
    fis.create_target_account_configuration(experimentTemplateId=template_a, accountId=account_id, roleArn=target_role_arn)
    ctx.on_cleanup(
        lambda: fis.delete_target_account_configuration(experimentTemplateId=template_a, accountId=account_id)
    )

    template_b = _create_template_retrying(ctx, fis, role_arn, "sim2real-xexp-b-", multi_account=False)
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_b))

    exp_a = _start_experiment_retrying(ctx, fis, template_a)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, exp_a))
    exp_b = _start_experiment_retrying(ctx, fis, template_b)
    ctx.on_cleanup(lambda: _stop_experiment_quiet(fis, exp_b))

    # Positive control: the account config is genuinely attached to experiment A.
    got = _poll_until_target_account_configuration(fis, exp_a, account_id)
    assert got["accountId"] == account_id, f"expected accountId {account_id!r}, got {got['accountId']!r}"

    # Negative: the same accountId does not exist as a configuration under experiment B.
    code, message = _error(
        lambda: fis.get_experiment_target_account_configuration(experimentId=exp_b, accountId=account_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"TargetAccountConfiguration for experiment {exp_b} and target account {account_id} not found"
    assert message == expected, f"expected {expected!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _poll_until_target_account_configuration(fis, experiment_id: str, account_id: str, timeout_s: float = 30.0, interval_s: float = 2.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fis.get_experiment_target_account_configuration(experimentId=experiment_id, accountId=account_id)[
                "targetAccountConfiguration"
            ]
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(
        f"target account configuration for {account_id} never appeared on experiment {experiment_id}: {last_err}"
    )


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


def _create_template_retrying(ctx, fis, role_arn: str, prefix: str, multi_account: bool, timeout_s: float = 30.0) -> str:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    kwargs = dict(
        stopConditions=[{"source": "none"}],
        targets={},
        actions={"waitAction": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
        roleArn=role_arn,
        tags={"sim2real:managed": "true"},
    )
    if multi_account:
        kwargs["experimentOptions"] = {"accountTargeting": "multi-account"}
    while time.monotonic() < deadline:
        try:
            return fis.create_experiment_template(
                clientToken=ctx.unique_name(f"{prefix}tok-"),
                description=ctx.unique_name(prefix),
                **kwargs,
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


# Upper bound on the cleanup wait while GetExperiment lags the final experiment state.
_CLEANUP_S = 900.0


def _stop_experiment_quiet(fis, experiment_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # An experiment already in a final state rejects StopExperiment (ValidationException) and
        # needs no stop; GetExperiment can lag that state, so it is polled every 2 s.
        lag_s = _CLEANUP_S - 120.0 if e.response["Error"]["Code"] == "ValidationException" else 0.0
        deadline = time.monotonic() + lag_s
        while fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"] not in (
                "stopping", "stopped", "completed", "failed", "cancelled"):
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
