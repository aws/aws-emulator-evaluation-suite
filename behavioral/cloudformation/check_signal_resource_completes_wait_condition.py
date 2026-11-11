"""signal-resource-completes-wait-condition."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "signal-resource-completes-wait-condition"
GROUP = "server-side"
SERVICES = ["cloudformation"]

_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A JSON signal PUT to a WaitConditionHandle's presigned URL completes the WaitCondition, so the stack
    reaches CREATE_COMPLETE and its Fn::GetAtt Data output maps the signal's UniqueId to the sent Data
    (SignalResource does not apply to a WaitCondition with a handle)."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-signalres-")

    template = {
        "Resources": {
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Wait": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {
                    "Handle": {"Ref": "Handle"},
                    "Timeout": "600",
                    "Count": "1",
                },
            },
        },
        "Outputs": {"WaitData": {"Value": {"Fn::GetAtt": ["Wait", "Data"]}}},
    }

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))

    handle_url = _get_handle_url(cfn, stack_id, timeout_s=60.0)
    unique_id = ctx.unique_name("sig-")
    data_payload = ctx.unique_name("data-")
    _signal_handle_with_retry(ctx, handle_url, unique_id, data_payload, timeout_s=60.0)

    status = _wait_stack_terminal(cfn, stack_id, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", (
        f"stack should have completed shortly after signaling the WaitConditionHandle, got {status} "
        "(if this timed out at ~600s, the signal was likely ignored)"
    )

    # The status transition alone doesn't prove the signaled payload actually reached
    # the resource -- an independent read of the stack's own Output (Fn::GetAtt Wait.Data)
    # must reflect the exact UniqueId/Data pair this run sent, not just that *something*
    # unblocked creation.
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])
    }
    assert "WaitData" in outputs, f"stack has no WaitData output: {outputs}"
    wait_data = json.loads(outputs["WaitData"])
    assert wait_data.get(unique_id) == data_payload, (
        f"WaitCondition Data attribute {wait_data!r} does not contain "
        f"{unique_id!r} -> {data_payload!r} from the signal this run sent"
    )


def _get_handle_url(cfn, stack_id: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            detail = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Handle")
            url = detail["StackResourceDetail"].get("PhysicalResourceId")
            if url:
                return url
        except ClientError as exc:
            last_err = exc
        time.sleep(2)
    raise AssertionError(f"WaitConditionHandle URL was not available within {timeout_s}s: {last_err}")


def _signal_handle_with_retry(ctx, handle_url: str, unique_id: str, data_payload: str, timeout_s: float) -> None:
    body = json.dumps(
        {
            "Status": "SUCCESS",
            "Reason": "sim2real check signal",
            "UniqueId": unique_id,
            "Data": data_payload,
        }
    ).encode("utf-8")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            # Presigned S3 PUT URLs are signature-sensitive about headers; send none beyond
            # an explicitly empty Content-Type, matching CloudFormation's documented signaling
            # instructions for WaitConditionHandle URLs.
            req = _routed_request(ctx, handle_url, data=body, method="PUT", headers={"Content-Type": ""})
            with urllib.request.urlopen(req, timeout=30) as resp:
                if 200 <= resp.status < 300:
                    return
                last_err = f"HTTP {resp.status}"
        except urllib.error.URLError as exc:
            last_err = exc
        time.sleep(2)
    raise AssertionError(f"could not signal WaitConditionHandle within {timeout_s}s: {last_err}")


def _wait_stack_terminal(cfn, stack_name: str, timeout_s: float = 180.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            return "DELETE_COMPLETE"
        status = stacks[0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach terminal status within {timeout_s}s (last={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
