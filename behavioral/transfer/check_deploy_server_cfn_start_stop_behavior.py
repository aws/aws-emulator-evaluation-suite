"""deploy-server-cfn-start-stop-behavior."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-server-cfn-start-stop-behavior"
GROUP = "deploy"
SERVICES = ["transfer"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Server:
    Type: AWS::Transfer::Server
    Properties:
      Protocols:
        - SFTP
      EndpointType: PUBLIC
      IdentityProviderType: SERVICE_MANAGED
Outputs:
  ServerId:
    Value: !GetAtt Server.ServerId
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A Transfer Server deployed via CloudFormation reaches CREATE_COMPLETE and
    genuinely accepts StartServer/StopServer, which flip DescribeServer's State."""
    cfn = ctx.client("cloudformation")
    transfer = ctx.client("transfer")

    stack_name = ctx.unique_name("sim2real-transfer-server-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    final = _poll_stack(cfn, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert final == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {final}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    }
    server_id = outputs["ServerId"]

    # A freshly-created server settles into either OFFLINE or ONLINE before any
    # StartServer/StopServer call; whichever it is, drive it through a full
    # start->stop (or stop->start) cycle and assert both transitions land.
    initial_state = _poll_until(
        lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
        lambda state: state in ("OFFLINE", "ONLINE"),
        timeout_s=300.0,
        interval_s=10.0,
    )

    if initial_state == "OFFLINE":
        transfer.start_server(ServerId=server_id)
        state = _poll_until(
            lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s == "ONLINE",
            timeout_s=240.0,
            interval_s=10.0,
        )
        assert state == "ONLINE", "StartServer did not bring the server ONLINE"

        transfer.stop_server(ServerId=server_id)
        state = _poll_until(
            lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s == "OFFLINE",
            timeout_s=240.0,
            interval_s=10.0,
        )
        assert state == "OFFLINE", "StopServer did not bring the server OFFLINE"
    else:
        transfer.stop_server(ServerId=server_id)
        state = _poll_until(
            lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s == "OFFLINE",
            timeout_s=240.0,
            interval_s=10.0,
        )
        assert state == "OFFLINE", "StopServer did not bring the server OFFLINE"

        transfer.start_server(ServerId=server_id)
        state = _poll_until(
            lambda: transfer.describe_server(ServerId=server_id)["Server"]["State"],
            lambda s: s == "ONLINE",
            timeout_s=240.0,
            interval_s=10.0,
        )
        assert state == "ONLINE", "StartServer did not bring the server ONLINE"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _poll_stack(cfn, stack_name, terminal_statuses):
    def _status():
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]

    return _poll_until(_status, lambda s: s in terminal_statuses, timeout_s=300.0, interval_s=10.0)


def _delete_stack(cfn, stack_name) -> None:
    cfn.delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status_or_gone(cfn, stack_name),
        lambda s: s in ("DELETE_COMPLETE", "GONE"),
        timeout_s=300.0,
        interval_s=10.0,
    )


def _stack_status_or_gone(cfn, stack_name):
    from botocore.exceptions import ClientError

    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return "GONE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
