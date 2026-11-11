"""notebook-lifecycle-config-applied-server-side."""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-lifecycle-config-applied-server-side"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A notebook instance with an attached lifecycle config runs its OnCreate hook server-side
    before reaching InService, shown by the hook's output in the platform's CloudWatch Logs
    stream rather than by the config merely being stored."""
    sm = ctx.client("sagemaker")
    ctx.client("logs")
    role_arn = _create_sagemaker_role(ctx)

    marker = ctx.unique_name("sim2real-marker-")
    script = f"#!/bin/bash\nset -e\necho \"{marker}\"\n"
    content = base64.b64encode(script.encode()).decode()

    lc_name = ctx.unique_name("sim2real-lc-")
    sm.create_notebook_instance_lifecycle_config(
        NotebookInstanceLifecycleConfigName=lc_name,
        OnCreate=[{"Content": content}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_notebook_instance_lifecycle_config(NotebookInstanceLifecycleConfigName=lc_name))

    nb_name = ctx.unique_name("sim2real-nb-")
    _create_notebook_instance_with_role_propagation_retry(
        sm,
        NotebookInstanceName=nb_name,
        InstanceType="ml.t3.medium",
        RoleArn=role_arn,
        LifecycleConfigName=lc_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_notebook_instance(ctx, nb_name))

    log_group = "/aws/sagemaker/NotebookInstances"
    log_stream = f"{nb_name}/LifecycleConfigOnCreate"

    found_marker = False
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        status = sm.describe_notebook_instance(NotebookInstanceName=nb_name)["NotebookInstanceStatus"]
        if _log_stream_contains(ctx, log_group, log_stream, marker):
            found_marker = True
            break
        if status == "Failed":
            raise AssertionError("notebook instance entered Failed before the OnCreate hook was observed")
        time.sleep(2)

    assert found_marker, (
        f"OnCreate lifecycle hook output {marker!r} never appeared in CloudWatch Logs "
        f"stream {log_group}/{log_stream} - the lifecycle config was stored but not executed"
    )

    # The instance still needs to reach InService once the hook has run.
    _wait_notebook_status(ctx, nb_name, "InService")


def _create_sagemaker_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    for _ in range(15):
        try:
            iam.get_role(RoleName=role_name)
            break
        except ClientError:
            time.sleep(2)
    return role["Arn"]


def _create_notebook_instance_with_role_propagation_retry(sm: Any, **kwargs: Any) -> None:
    deadline = time.monotonic() + 60
    while True:
        try:
            sm.create_notebook_instance(**kwargs)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] == "ValidationException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _log_stream_contains(ctx: Any, log_group: str, log_stream: str, needle: str) -> bool:
    logs = ctx.client("logs")
    try:
        resp = logs.get_log_events(logGroupName=log_group, logStreamName=log_stream, startFromHead=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException",):
            return False
        raise
    return any(needle in e.get("message", "") for e in resp.get("events", []))


def _wait_notebook_status(ctx: Any, nb_name: str, want: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = sm.describe_notebook_instance(NotebookInstanceName=nb_name)["NotebookInstanceStatus"]
        if status == want:
            return
        if status == "Failed":
            raise AssertionError(f"notebook instance entered Failed while waiting for {want}")
        time.sleep(interval_s)
    raise AssertionError(f"notebook instance did not reach {want} within {timeout_s}s")


def _cleanup_notebook_instance(ctx: Any, nb_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_notebook_instance(NotebookInstanceName=nb_name)["NotebookInstanceStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationException":
            return
        raise
    # StopNotebookInstance is accepted only InService, so wait out Pending/Updating first.
    deadline = time.monotonic() + 600
    stop_requested = False
    while status not in ("Stopped", "Failed", "Deleting"):
        if status == "InService" and not stop_requested:
            sm.stop_notebook_instance(NotebookInstanceName=nb_name)
            stop_requested = True
        if time.monotonic() >= deadline:
            raise AssertionError(f"notebook instance {nb_name} still {status} after 600s of teardown")
        time.sleep(2)
        status = sm.describe_notebook_instance(NotebookInstanceName=nb_name)["NotebookInstanceStatus"]
    if status != "Deleting":
        sm.delete_notebook_instance(NotebookInstanceName=nb_name)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            sm.describe_notebook_instance(NotebookInstanceName=nb_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                return
            raise
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
