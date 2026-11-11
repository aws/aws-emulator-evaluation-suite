"""stop-completed-experiment-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-completed-experiment-rejected"
GROUP = "state-machine"
SERVICES = ["fis"]


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html
@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:fis-active-experiment-quota", "timing:real-time")
def run(ctx) -> None:
    """StopExperiment on a completed experiment fails with ValidationException and its exact message and leaves its
    status and endTime unchanged, while a running experiment stops (status "stopped")."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)

    # --- negative: try to stop an experiment that already finished ---
    completed_template_id = _create_experiment_template(
        ctx,
        role_arn,
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
    )
    completed_start = _start_experiment_with_retry(fis, completed_template_id, ctx)
    completed_experiment_id = completed_start["experiment"]["id"]

    def completed_status_probe() -> str:
        return fis.get_experiment(id=completed_experiment_id)["experiment"]["state"]["status"]

    _poll_until(completed_status_probe, lambda s: s == "completed", timeout_s=180.0, interval_s=3.0)
    before = fis.get_experiment(id=completed_experiment_id)["experiment"]
    assert before["state"]["status"] == "completed", (
        f"expected the wait-only experiment to have reached completed, got {before['state']['status']!r}"
    )
    end_time_before = before["endTime"]

    code, message = _error(lambda: fis.stop_experiment(id=completed_experiment_id))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = f"Cannot modify the state of an experiment in final state: {completed_experiment_id}."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after = fis.get_experiment(id=completed_experiment_id)["experiment"]
    assert after["state"]["status"] == "completed", "rejected StopExperiment must not change state"
    assert after["endTime"] == end_time_before, "rejected StopExperiment must not touch endTime"

    # --- positive control: a still-running experiment can be stopped ---
    running_template_id = _create_experiment_template(
        ctx,
        role_arn,
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT5M"}}},
    )
    running_start = _start_experiment_with_retry(fis, running_template_id, ctx)
    running_experiment_id = running_start["experiment"]["id"]

    def running_status_probe() -> str:
        return fis.get_experiment(id=running_experiment_id)["experiment"]["state"]["status"]

    _poll_until(running_status_probe, lambda s: s == "running", timeout_s=60.0, interval_s=2.0)
    fis.stop_experiment(id=running_experiment_id)
    final_state = _poll_until(
        running_status_probe,
        lambda s: s in ("stopped", "failed", "cancelled", "completed"),
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert final_state == "stopped", f"positive control expected the experiment to stop, got {final_state!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    emulator accepting what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    timeout_s: float = 120.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _create_fis_role(ctx, managed_policy_arns: tuple[str, ...] = ()) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-fis-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "fis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:fis:{ctx.region}:{account_id}:experiment/*"
                    },
                },
            }
        ],
    }
    import json

    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-fis"},
        ],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
        )
    return role_arn


def _create_experiment_template(
    ctx,
    role_arn: str,
    actions: dict,
    targets: dict | None = None,
    stop_conditions: list | None = None,
    description: str | None = None,
) -> str:
    fis = ctx.client("fis")
    kwargs: dict[str, Any] = {
        "clientToken": ctx.unique_name("sim2real-fis-tok-"),
        "description": description or "sim2real fis behavioral check",
        "stopConditions": stop_conditions or [{"source": "none"}],
        "actions": actions,
        "roleArn": role_arn,
        "targets": targets or {},
        "tags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-fis"},
    }

    last_exc: ClientError | None = None
    resp = None
    for attempt in range(10):
        try:
            resp = fis.create_experiment_template(**kwargs)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "ValidationException") and attempt < 9:
                last_exc = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        assert last_exc is not None, "create_experiment_template retry loop exited with no response and no captured error"
        raise last_exc

    template_id = resp["experimentTemplate"]["id"]
    ctx.on_cleanup(lambda: fis.delete_experiment_template(id=template_id))
    return template_id


def _start_experiment_with_retry(fis, template_id: str, ctx, timeout_s: float = 60.0):
    """StartExperiment can transiently fail with ValidationException("Unable to assume
    role ...") while a freshly-created IAM role/policy attachment is still propagating
    through STS; retry until that clears or the timeout elapses."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fis.start_experiment(
                clientToken=ctx.unique_name("sim2real-fis-start-"),
                experimentTemplateId=template_id,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ValidationException" and "assume role" in message.lower():
                last_exc = exc
                time.sleep(3)
                continue
            raise
    assert last_exc is not None, f"start_experiment did not succeed within {timeout_s}s and no error was captured"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
