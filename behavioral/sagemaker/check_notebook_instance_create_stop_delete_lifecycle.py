"""notebook-instance-create-stop-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "notebook-instance-create-stop-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateNotebookInstance reaches InService; it must be Stopped before DeleteNotebookInstance
    succeeds, then a later DescribeNotebookInstance 404s."""
    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    role_arn = _create_execution_role(ctx, iam)

    name = ctx.unique_name("sim2real-sm-nbi-")

    def _create():
        return sm.create_notebook_instance(
            NotebookInstanceName=name,
            InstanceType="ml.t3.medium",
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": "notebook-instance-lifecycle"}],
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: _teardown_notebook_instance(ctx, name))

    _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=name),
        lambda r: r["NotebookInstanceStatus"] in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    described = sm.describe_notebook_instance(NotebookInstanceName=name)
    assert described["NotebookInstanceStatus"] == "InService", (
        f"expected InService after create, got {described['NotebookInstanceStatus']!r}"
    )
    assert described["RoleArn"] == role_arn, (
        f"expected RoleArn {role_arn!r}, got {described['RoleArn']!r}"
    )

    sm.stop_notebook_instance(NotebookInstanceName=name)
    _poll_until(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=name),
        lambda r: r["NotebookInstanceStatus"] == "Stopped",
        timeout_s=600.0,
        interval_s=15.0,
    )

    sm.delete_notebook_instance(NotebookInstanceName=name)

    gone_code, gone_message = _poll_until_gone(
        lambda: sm.describe_notebook_instance(NotebookInstanceName=name), timeout_s=120.0, interval_s=5.0
    )
    assert gone_code == "ValidationException", gone_code
    assert gone_message == "RecordNotFound", gone_message

    stop_after_delete_code, stop_after_delete_message = _error(
        lambda: sm.stop_notebook_instance(NotebookInstanceName=name)
    )
    assert stop_after_delete_code == "ValidationException", (
        f"expected StopNotebookInstance on a deleted instance to fail with ValidationException, "
        f"got {stop_after_delete_code!r}"
    )
    assert stop_after_delete_message == (
        f"Notebook Instance {described['NotebookInstanceArn']} does not exist"
    ), stop_after_delete_message


def _notebook_gone(err) -> bool:
    """SageMaker reports a missing notebook instance as ValidationException 'RecordNotFound'
    (describe) or '... does not exist' (stop/delete)."""
    error = err.response["Error"]
    message = error.get("Message", "")
    return error["Code"] == "ValidationException" and (message == "RecordNotFound" or "does not exist" in message)


def _teardown_notebook_instance(ctx, name: str) -> None:
    """Stop the instance (waiting out Pending/Updating/Stopping) and delete it; an instance
    already gone or Deleting returns, any other failure raises. Bounded at 600 s."""
    sm = ctx.client("sagemaker")
    deadline = time.monotonic() + 600.0
    stop_requested = False
    while True:
        try:
            status = sm.describe_notebook_instance(NotebookInstanceName=name)["NotebookInstanceStatus"]
        except ClientError as err:
            if _notebook_gone(err):
                return
            raise
        if status == "Deleting":
            return
        if status in ("Stopped", "Failed"):
            break
        if status == "InService" and not stop_requested:
            sm.stop_notebook_instance(NotebookInstanceName=name)
            stop_requested = True
        if time.monotonic() >= deadline:
            raise AssertionError(f"notebook instance {name} still {status} after 600s of teardown")
        time.sleep(2)
    try:
        sm.delete_notebook_instance(NotebookInstanceName=name)
    except ClientError as err:
        if not _notebook_gone(err):
            raise


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until_gone(describe, *, timeout_s: float, interval_s: float):
    """Call describe() until it raises; return (code, message). Raises if it still succeeds
    at the deadline."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            describe()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"notebook instance still described {timeout_s}s after delete")
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_execution_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "notebook-instance-lifecycle"}],
    )
    role_arn = role["Role"]["Arn"]

    def _cleanup():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
