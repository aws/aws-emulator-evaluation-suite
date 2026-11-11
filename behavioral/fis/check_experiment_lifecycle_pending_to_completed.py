"""experiment-lifecycle-pending-to-completed."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-lifecycle-pending-to-completed"
GROUP = "state-machine"
SERVICES = ["fis"]


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html
@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:fis-active-experiment-quota", "timing:real-time")
def run(ctx) -> None:
    """StartExperiment on a template using the built-in aws:fis:wait action (no target
    resources or permissions required) drives the experiment through
    pending -> initiating -> running -> completed, observed purely via GetExperiment polling."""
    fis = ctx.client("fis")
    role_arn = _create_fis_role(ctx)
    template_id = _create_experiment_template(
        ctx,
        role_arn,
        actions={"wait": {"actionId": "aws:fis:wait", "parameters": {"duration": "PT1M"}}},
    )

    start = _start_experiment_with_retry(fis, template_id, ctx)
    experiment_id = start["experiment"]["id"]
    assert start["experiment"]["state"]["status"] in ("pending", "initiating")

    valid_order = ["pending", "initiating", "running", "completed"]
    observed: list[str] = []

    def probe() -> str:
        return fis.get_experiment(id=experiment_id)["experiment"]["state"]["status"]

    deadline = time.monotonic() + 180.0
    status = probe()
    while time.monotonic() < deadline:
        status = probe()
        if not observed or observed[-1] != status:
            observed.append(status)
        if status == "completed":
            break
        if status in ("stopped", "failed", "cancelled"):
            raise AssertionError(f"experiment reached unexpected terminal state {status!r}")
        time.sleep(3)

    assert status == "completed", f"experiment did not reach completed within 180s; observed={observed}"
    assert "running" in observed, f"expected to observe the running state; observed={observed}"

    # every distinct observed status must move strictly forward through the documented order
    indices = [valid_order.index(s) for s in observed]
    assert indices == sorted(indices) and len(set(indices)) == len(indices), (
        f"observed experiment states were not strictly increasing: {observed}"
    )

    final = fis.get_experiment(id=experiment_id)["experiment"]
    assert final["state"]["status"] == "completed"
    assert "startTime" in final and "endTime" in final


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        "tags": {"sim2real-check": CHECK},
    }

    # newly-created IAM roles can take a few seconds to become assumable/visible; retry the
    # transient ResourceNotFoundException/ValidationException the service returns meanwhile.
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
        assert last_exc is not None
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
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
