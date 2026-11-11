"""create-resource-unsupported-type-target-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-resource-unsupported-type-target-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateResource and GetResource on a NON_PROVISIONABLE type are UnsupportedActionException.

    The same CreateResource shape on AWS::SQS::Queue succeeds and the queue is readable.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-types.html
    """
    cfn = ctx.client("cloudformation")
    cc = ctx.client("cloudcontrol")

    # Discovered via ListTypes rather than hardcoded, as registry contents change.
    unsupported_type = _find_non_provisionable_type(cfn)
    if unsupported_type is None:
        raise AssertionError(
            "no NON_PROVISIONABLE public RESOURCE type is visible via "
            "cloudformation.list_types(ProvisioningType='NON_PROVISIONABLE') in this "
            "account/region right now; this category is a live AWS-managed registry "
            "snapshot this check cannot itself provision, so there is nothing to target "
            "for CreateResource in this environment"
        )

    code, message = _error(
        lambda: cc.create_resource(TypeName=unsupported_type, DesiredState="{}")
    )
    assert code == "UnsupportedActionException", f"unexpected code for {unsupported_type}: {code}"
    expected_message = f"Resource type {unsupported_type} does not support CREATE action"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejection is synchronous, so there is no request to poll; the type has no read handler.
    read_code, read_message = _error(
        lambda: cc.get_resource(TypeName=unsupported_type, Identifier="does-not-matter")
    )
    assert read_code == "UnsupportedActionException", f"unexpected code for read: {read_code}"
    expected_read_message = f"Resource type {unsupported_type} does not support READ action"
    assert read_message == expected_read_message, (
        f"expected message {expected_read_message!r}, got {read_message!r}"
    )

    queue_name = ctx.unique_name("sim2real-cc-utsupp-ctrl-")
    control_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": queue_name})
    )
    final = _poll_request_status(cc, control_resp["ProgressEvent"]["RequestToken"], timeout_s=150.0)
    assert final["OperationStatus"] == "SUCCESS", f"control create failed: {final}"
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=identifier))

    got = cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
    control_props = json.loads(got["ResourceDescription"]["Properties"])
    assert control_props.get("QueueName") == queue_name, (
        f"control queue not independently readable via GetResource: {control_props}"
    )


def _find_non_provisionable_type(cfn: Any) -> str | None:
    token = None
    for _ in range(20):
        kwargs = {
            "Visibility": "PUBLIC",
            "Type": "RESOURCE",
            "ProvisioningType": "NON_PROVISIONABLE",
            "DeprecatedStatus": "LIVE",
            "MaxResults": 100,
        }
        if token:
            kwargs["NextToken"] = token
        resp = cfn.list_types(**kwargs)
        summaries = resp.get("TypeSummaries", [])
        if summaries:
            return summaries[0]["TypeName"]
        token = resp.get("NextToken")
        if not token:
            break
    return None


def _error(fn) -> tuple[str | None, str | None]:
    """Call fn(); return its ClientError (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_request_status(cc: Any, request_token: str, timeout_s: float = 60.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(2.0)
    raise AssertionError(f"request never reached a terminal state: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
