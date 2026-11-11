"""ref-intrinsic-resolves."""
from __future__ import annotations

import json
import re
import time
from urllib.parse import parse_qs, unquote, urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ref-intrinsic-resolves"
GROUP = 'resources'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name

def _outputs_template(output_value="hello-sim2real"):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Outputs": {
            "HandleUrl": {"Description": "The presigned URL", "Value": {"Ref": "Handle"}},
            "StaticOutput": {"Description": "A static output value", "Value": output_value},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Ref to a WaitConditionHandle resolves to the resource's own reported physical id,
    a live SigV4-presigned S3 URL scoped to this stack — not merely some string."""
    cf = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = _create_and_wait(ctx, cf, _outputs_template())
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=name)["Stacks"][0].get("Outputs", [])
    }
    resource = cf.describe_stack_resource(StackName=name, LogicalResourceId="Handle")["StackResourceDetail"]

    assert "HandleUrl" in outputs, f"expected an Outputs entry named HandleUrl, got keys {sorted(outputs)}"
    handle_url = outputs["HandleUrl"]
    physical_id = resource.get("PhysicalResourceId")
    assert handle_url == physical_id, (
        f"Ref to the WaitConditionHandle in Outputs ({handle_url!r}) must equal the resource's own "
        f"PhysicalResourceId read independently via DescribeStackResource ({physical_id!r})"
    )

    parsed = urlparse(handle_url)
    assert parsed.scheme in ("http", "https"), f"expected an http(s) presigned URL, got scheme {parsed.scheme!r} in {handle_url!r}"
    assert re.fullmatch(r"[A-Za-z0-9.-]+(:\d+)?", parsed.netloc), f"expected a well-formed host, got {parsed.netloc!r} in {handle_url!r}"

    query = parse_qs(parsed.query)
    assert query.get("X-Amz-Algorithm") == ["AWS4-HMAC-SHA256"], (
        f"expected a SigV4-signed URL (X-Amz-Algorithm=AWS4-HMAC-SHA256), got query {query!r}"
    )
    assert query.get("X-Amz-Signature", [""])[0], f"missing/empty X-Amz-Signature in {handle_url!r}"
    assert query.get("X-Amz-Credential", [""])[0], f"missing/empty X-Amz-Credential in {handle_url!r}"

    decoded_path = unquote(parsed.path)
    expected_prefix = f"/arn:aws:cloudformation:{ctx.region}:{account_id}:stack/"
    assert decoded_path.startswith(expected_prefix) and decoded_path.endswith("/Handle"), (
        f"expected the URL path to carry this stack's own ARN (prefix {expected_prefix!r}) and end "
        f"in the logical id 'Handle', got {decoded_path!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
