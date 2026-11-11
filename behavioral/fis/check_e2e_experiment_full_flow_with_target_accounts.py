"""e2e-experiment-full-flow-with-target-accounts."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-experiment-full-flow-with-target-accounts"
GROUP = "e2e"
SERVICES = ["fis"]

_TERMINAL = {"completed", "stopped", "failed", "cancelled"}


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:fis-active-experiment-quota", "timing:real-time")
def run(ctx) -> None:
    """A multi-account experiment with a target account configuration really resolves a target
    through the configured account's role, and DeleteTargetAccountConfiguration plus
    DeleteExperimentTemplate really remove the wiring."""
    iam = ctx.client("iam")
    fis = ctx.client("fis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    # This account plays both roles ("orchestrator" and "target") via IAM role
    # chaining, since only one AWS account is available to the check -- but it
    # exercises the same CreateTargetAccountConfiguration/role-chain wiring FIS
    # uses for a genuinely separate target account.
    orchestrator_name = ctx.unique_name("sim2real-fis-orc-")
    orchestrator_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:fis:{region}:{account_id}:experiment/*"},
                },
            }
        ],
    }
    orchestrator_arn = iam.create_role(
        RoleName=orchestrator_name, AssumeRolePolicyDocument=json.dumps(orchestrator_trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, orchestrator_name, ["assume-target"]))
    iam.get_waiter("role_exists").wait(RoleName=orchestrator_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    target_chain_name = ctx.unique_name("sim2real-fis-tgt-")
    target_chain_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account_id},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringLike": {"sts:ExternalId": f"arn:aws:fis:{region}:{account_id}:experiment/*"},
                    "ArnEquals": {"aws:PrincipalArn": orchestrator_arn},
                },
            }
        ],
    }
    target_chain_arn = iam.create_role(
        RoleName=target_chain_name, AssumeRolePolicyDocument=json.dumps(target_chain_trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, target_chain_name, ["inject-api"]))
    iam.put_role_policy(
        RoleName=target_chain_name,
        PolicyName="inject-api",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "fis:InjectApiInternalError",
                            "fis:InjectApiThrottleError",
                            "fis:InjectApiUnavailableError",
                        ],
                        "Resource": "arn:*:fis:*:*:experiment/*",
                    }
                ],
            }
        ),
    )
    iam.get_waiter("role_exists").wait(RoleName=target_chain_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    # Now that the target-account chain role exists, grant the orchestrator role
    # permission to assume it.
    iam.put_role_policy(
        RoleName=orchestrator_name,
        PolicyName="assume-target",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": target_chain_arn}
                ],
            }
        ),
    )

    # An arbitrary IAM role whose (hypothetical) API calls the action will throttle.
    victim_name = ctx.unique_name("sim2real-fis-victim-")
    victim_arn = iam.create_role(
        RoleName=victim_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, victim_name, []))
    iam.get_waiter("role_exists").wait(RoleName=victim_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    template_id = fis.create_experiment_template(
        clientToken=ctx.unique_name("sim2real-fis-tmpl-tok-"),
        description="sim2real fis multi-account e2e check",
        targets={"myRole": {"resourceType": "aws:iam:role", "resourceArns": [victim_arn], "selectionMode": "ALL"}},
        actions={
            "ThrottleAPI": {
                "actionId": "aws:fis:inject-api-throttle-error",
                "parameters": {"service": "ec2", "operations": "DescribeInstances", "percentage": "100", "duration": "PT1M"},
                "targets": {"Roles": "myRole"},
            }
        },
        stopConditions=[{"source": "none"}],
        roleArn=orchestrator_arn,
        experimentOptions={"accountTargeting": "multi-account", "emptyTargetResolutionMode": "skip"},
        tags={"Name": "sim2real-fis-multi-account"},
    )["experimentTemplate"]["id"]

    def _cleanup_template():
        try:
            fis.delete_experiment_template(id=template_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_template)

    fis.create_target_account_configuration(
        experimentTemplateId=template_id,
        accountId=account_id,
        roleArn=target_chain_arn,
        description="sim2real target account",
    )

    def _cleanup_tac():
        try:
            fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_tac)

    experiment_id, final = _run_experiment_until_ready(ctx, template_id, overall_timeout_s=180.0)
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, experiment_id))
    assert final["state"]["status"] == "completed", final["state"]

    # The experiment actually resolved a target (not merely a config that was never used).
    resolved = fis.list_experiment_resolved_targets(experimentId=experiment_id)["resolvedTargets"]
    assert len(resolved) == 1, f"expected exactly 1 resolved target, got {resolved}"
    assert resolved[0]["resourceType"] == "aws:iam:role", resolved[0]
    assert resolved[0]["targetName"] == "myRole", resolved[0]

    # The experiment's frozen target account configuration matches what we configured.
    tac = fis.get_experiment_target_account_configuration(experimentId=experiment_id, accountId=account_id)[
        "targetAccountConfiguration"
    ]
    assert tac["accountId"] == account_id, f"expected accountId {account_id!r}, got {tac['accountId']!r}"
    assert tac["roleArn"] == target_chain_arn, f"expected roleArn {target_chain_arn!r}, got {tac['roleArn']!r}"

    # Tear the wiring down as part of the flow (not merely cleanup) and verify absence.
    fis.delete_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)
    tac_code, tac_message = _error(
        lambda: fis.get_target_account_configuration(experimentTemplateId=template_id, accountId=account_id)
    )
    assert tac_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {tac_code!r}"
    expected_tac = "TargetAccountConfiguration not found."
    assert tac_message == expected_tac, f"expected message {expected_tac!r}, got {tac_message!r}"

    fis.delete_experiment_template(id=template_id)
    tmpl_code, tmpl_message = _error(lambda: fis.get_experiment_template(id=template_id))
    assert tmpl_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {tmpl_code!r}"
    expected_tmpl = "ExperimentTemplate not found."
    assert tmpl_message == expected_tmpl, f"expected message {expected_tmpl!r}, got {tmpl_message!r}"


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


def _delete_role(ctx: Any, role_name: str, inline_policy_names: list[str]) -> None:
    iam = ctx.client("iam")
    for policy_name in inline_policy_names:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_stop(ctx: Any, experiment_id: str) -> None:
    fis = ctx.client("fis")
    try:
        exp = fis.get_experiment(id=experiment_id)["experiment"]
        if exp["state"]["status"] not in _TERMINAL:
            fis.stop_experiment(id=experiment_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        # an experiment already in a final state rejects StopExperiment; it needs no stop
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        if status not in _TERMINAL | {"stopping"}:
            raise


def _start_experiment_with_retry(
    ctx: Any, template_id: str, timeout_s: float = 60.0, interval_s: float = 5.0
) -> str:
    # Freshly-created IAM roles (and the role-chaining trust between them) can lag
    # a few seconds before AWS FIS can reliably assume them across the chain (IAM
    # is eventually consistent). Retry with a fresh clientToken rather than fail
    # on that transient propagation window.
    fis = ctx.client("fis")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-tok-"),
                experimentTemplateId=template_id,
            )
            return resp["experiment"]["id"]
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code in ("ConflictException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"StartExperiment kept failing with {last_code} for {timeout_s}s")


def _poll_experiment_terminal(
    ctx: Any, experiment_id: str, timeout_s: float = 180.0, interval_s: float = 5.0
) -> dict[str, Any]:
    fis = ctx.client("fis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        exp = fis.get_experiment(id=experiment_id)["experiment"]
        if exp["state"]["status"] in _TERMINAL:
            return exp
        time.sleep(interval_s)
    raise AssertionError(f"experiment {experiment_id} did not reach a terminal state within {timeout_s}s")


def _is_role_chain_propagation_failure(state: dict[str, Any]) -> bool:
    error_code = state.get("error", {}).get("code")
    reason = state.get("reason", "")
    return error_code == "AuthorizationFailure" and "AssumeRole" in reason


def _run_experiment_until_ready(
    ctx: Any, template_id: str, overall_timeout_s: float = 180.0
) -> tuple[str, dict[str, Any]]:
    # The orchestrator -> target-account-role assume-role chain and its inline
    # policies can still be mid-propagation when FIS actually executes the
    # experiment, even though StartExperiment already succeeded and
    # role_exists confirmed both roles are present -- observed on real AWS as a
    # terminal "failed"/AuthorizationFailure naming the AssumeRole hop, not a
    # rejection at StartExperiment time. Retry the whole start+run attempt
    # (fresh clientToken, fresh experiment) within one bounded window, the same
    # propagation allowance _start_experiment_with_retry already gives the
    # StartExperiment call itself.
    deadline = time.monotonic() + overall_timeout_s
    exp = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        experiment_id = _start_experiment_with_retry(ctx, template_id, timeout_s=min(90.0, remaining))
        exp = _poll_experiment_terminal(ctx, experiment_id, timeout_s=max(remaining, 30.0))
        if exp["state"]["status"] == "completed" or not _is_role_chain_propagation_failure(exp["state"]):
            return experiment_id, exp
        if time.monotonic() >= deadline:
            return experiment_id, exp
        time.sleep(5.0)
    raise AssertionError(f"could not start-and-run an experiment within {overall_timeout_s}s: {exp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
