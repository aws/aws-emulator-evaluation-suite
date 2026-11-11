"""create-notebook-instance-nonexistent-role-arn-accepted-then-fails."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-notebook-instance-nonexistent-role-arn-accepted-then-fails"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateNotebookInstance accepts a well-formed RoleArn naming no real role and fails only
    at provisioning, while an identical request with a real, assumable role reaches InService."""
    sm = ctx.client("sagemaker")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bad_name = ctx.unique_name("sim2real-nb-bad-")
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-nb-noexist-')}"

    sm.create_notebook_instance(
        NotebookInstanceName=bad_name,
        InstanceType="ml.t3.medium",
        RoleArn=bogus_role_arn,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_notebook(ctx, bad_name))

    bad_status, bad_failure_reason = _await_terminal_status(ctx, bad_name)
    assert bad_status == "Failed", (
        f"expected provisioning against a nonexistent role to fail, got {bad_status!r}"
    )
    assert bad_failure_reason, "a Failed notebook instance must report a non-empty FailureReason"

    role_arn, role_name = _create_exec_role(ctx)
    good_name = ctx.unique_name("sim2real-nb-good-")
    sm.create_notebook_instance(
        NotebookInstanceName=good_name,
        InstanceType="ml.t3.medium",
        RoleArn=role_arn,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_notebook(ctx, good_name))

    good_status, good_failure_reason = _await_terminal_status(ctx, good_name)
    assert good_status == "InService", (
        f"expected the real-role notebook instance to reach InService, got {good_status!r} ({good_failure_reason!r})"
    )


_POLL_INTERVAL_S = 2.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _await_terminal_status(
    ctx,
    name: str,
    terminal: tuple[str, ...] = ("InService", "Failed"),
    timeout_s: float = 600.0,
    bounded: bool = True,
):
    sm = ctx.client("sagemaker")
    if bounded:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        desc = sm.describe_notebook_instance(NotebookInstanceName=name)
        status = desc["NotebookInstanceStatus"]
        if status in terminal:
            return status, desc.get("FailureReason")
        if time.monotonic() >= deadline:
            if bounded and _budget_spent(ctx):
                raise TimeoutError(f"notebook instance {name} to reach a terminal state: the run budget ended first; not graded")
            raise AssertionError(
                f"notebook instance {name} did not reach a terminal state within {timeout_s:.0f}s "
                f"(last status {status!r})"
            )
        time.sleep(_POLL_INTERVAL_S)


def _create_exec_role(ctx) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    ctx.on_cleanup(lambda: _delete_exec_role(ctx, role_name))
    return role_arn, role_name


def _delete_exec_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
        return
    failures = []
    steps = [lambda a=pol["PolicyArn"]: iam.detach_role_policy(RoleName=role_name, PolicyArn=a)
             for pol in attached] + [lambda: iam.delete_role(RoleName=role_name)]
    for step in steps:
        try:
            step()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                failures.append(exc)
    if failures:
        raise RuntimeError(f"iam role {role_name} was not deleted: {failures!r}")


def _notebook_gone(exc: ClientError) -> bool:
    """SageMaker answers an unknown notebook instance with ValidationException RecordNotFound."""
    err = exc.response["Error"]
    return err["Code"] == "ValidationException" and "RecordNotFound" in err.get("Message", "")


def _teardown_notebook(ctx, name: str) -> None:
    sm = ctx.client("sagemaker")
    status = None
    try:
        status, _ = _await_terminal_status(ctx, name, timeout_s=900.0, bounded=False)
    except ClientError as exc:
        if not _notebook_gone(exc):
            raise
        return
    except AssertionError as last:
        raise RuntimeError(f"notebook instance {name} was not deleted: {last!r}") from last
    try:
        if status == "InService":
            sm.stop_notebook_instance(NotebookInstanceName=name)
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                status = sm.describe_notebook_instance(NotebookInstanceName=name)["NotebookInstanceStatus"]
                if status == "Stopped":
                    break
                time.sleep(_POLL_INTERVAL_S)
            else:
                raise RuntimeError(f"notebook instance {name} was not deleted: still {status!r} after stop")
        sm.delete_notebook_instance(NotebookInstanceName=name)
    except ClientError as exc:
        if not _notebook_gone(exc):
            raise RuntimeError(f"notebook instance {name} was not deleted: {exc!r}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
