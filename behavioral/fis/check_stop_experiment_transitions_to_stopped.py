"""stop-experiment-transitions-to-stopped."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-experiment-transitions-to-stopped"
GROUP = "state-machine"
SERVICES = ["fis"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota")
def run(ctx) -> None:
    """StopExperiment on a running experiment (a 5-minute aws:fis:wait action gives ample
    window to intervene) moves the experiment to a stopped terminal state, and subsequent
    GetExperiment calls keep reflecting that terminal state rather than reverting to running."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_experiment_template(
        ctx,
        role_arn,
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT5M"}}},
    )

    start = _start_experiment_with_retry(fis, template_id, ctx)
    experiment_id = start["experiment"]["id"]

    def status_probe() -> str:
        return fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]

    running_state = _poll_until(status_probe, lambda s: s == "running", timeout_s=60.0, interval_s=2.0)
    assert running_state == "running", f"expected the experiment to reach running, got {running_state!r}"

    stop_resp = fis.stop_experiment(id=experiment_id)
    stop_status = stop_resp["experiment"]["state"]["status"]
    assert stop_status in ("stopping", "stopped"), (
        f"expected StopExperiment's own response to report stopping/stopped, got {stop_status!r}"
    )

    final_state = _poll_until(
        status_probe,
        lambda s: s in ("stopped", "failed", "cancelled", "completed"),
        timeout_s=120.0,
        interval_s=2.0,
    )
    assert final_state == "stopped", f"expected the experiment to stop, got {final_state!r}"

    final = fis.get_experiment(id=experiment_id)["experiment"]
    assert final["state"]["status"] == "stopped", (
        f"independent GetExperiment expected stopped, got {final['state']['status']!r}"
    )
    assert "endTime" in final, "a stopped experiment must report an endTime"

    # freeze detector: a stopped experiment is terminal and must not revert to running on
    # later reads, spaced out rather than sampled once
    for attempt in range(3):
        time.sleep(2)
        status = fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]
        assert status == "stopped", (
            f"terminal state reverted on read {attempt + 1}/3: expected stopped, got {status!r}"
        )


def _error_code(fn: Callable[[], Any]) -> str | None:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
        "tags": {"sim2real:managed": "true"},
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
        assert last_exc is not None, "no response and no captured exception from the retry loop"
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
    assert last_exc is not None, "start_experiment retry loop exited with no captured exception"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

