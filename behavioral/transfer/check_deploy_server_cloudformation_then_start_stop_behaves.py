"""deploy-server-cloudformation-then-start-stop-behaves."""
from __future__ import annotations

import time
from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-server-cloudformation-then-start-stop-behaves"
GROUP = "deploy"
SERVICES = ["transfer"]


_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  TransferServer:
    Type: AWS::Transfer::Server
    Properties:
      EndpointType: PUBLIC
      IdentityProviderType: SERVICE_MANAGED
      Protocols:
        - SFTP
      Tags:
        - Key: sim2real
          Value: behavioral
Outputs:
  ServerId:
    Value: !GetAtt TransferServer.ServerId
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Transfer::Server is describable, reaches ONLINE/OFFLINE on
    StartServer/StopServer, and is gone (ResourceNotFoundException) after the stack is deleted."""
    transfer = ctx.client("transfer")

    deployed = _deploy_cfn(ctx, _TEMPLATE)
    server_id = deployed["outputs"]["ServerId"]
    stack_name = deployed["stack_name"]

    # Independent read: the stack output names a real, describable server.
    described = transfer.describe_server(ServerId=server_id)["Server"]
    assert described["ServerId"] == server_id, (
        f"describe_server ServerId mismatch: expected {server_id!r}, got {described.get('ServerId')!r}"
    )

    transfer.start_server(ServerId=server_id)
    _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda state: state == "ONLINE",
        timeout_s=300.0,
        interval_s=10.0,
        what="server State to reach ONLINE after StartServer",
    )

    transfer.stop_server(ServerId=server_id)
    _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda state: state == "OFFLINE",
        timeout_s=300.0,
        interval_s=10.0,
        what="server State to reach OFFLINE after StopServer",
    )

    # The stack owns the server; deleting it must delete the server, not just reach DELETE_COMPLETE.
    _delete_stack_and_wait(ctx, stack_name)
    error = _client_error(lambda: transfer.describe_server(ServerId=server_id))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a server deleted via its owning stack, got {error!r}"
    )
    assert error.get("Message") == "Unknown server", f"unexpected not-found message: {error!r}"


def _poll_until(
    probe: Callable[[], object],
    predicate: Callable[[object], bool],
    *,
    timeout_s: float,
    interval_s: float,
    what: str,
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last observed value={last!r}")


def _client_error(fn: Callable[[], object]) -> dict:
    """The botocore Error dict of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CloudFormation stack (a no-op if already deleted) and wait for DELETE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=180.0,
        interval_s=5.0,
        what=f"stack {stack_name} to reach DELETE_COMPLETE",
    )


def _deploy_cfn(ctx, template: str, *, stack_name: str | None = None, timeout_s: float = 300.0) -> dict:
    """Deploy a CloudFormation stack; wait for CREATE_COMPLETE; register delete-stack-and-wait
    teardown. Returns {stack_name, stack_id, outputs:{k: v}}."""
    cfn = ctx.client("cloudformation")
    name = stack_name or ctx.unique_name("sim2real-transfer-server-stack-")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        what=f"stack {name} to reach a terminal CREATE status",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
