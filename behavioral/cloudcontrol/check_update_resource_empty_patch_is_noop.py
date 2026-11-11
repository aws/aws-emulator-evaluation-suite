"""update-resource-empty-patch-is-noop."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-resource-empty-patch-is-noop"
GROUP = "error-semantics"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateResource with an empty JSON Patch document ("[]") completes as a
    genuine, idempotent no-op: OperationStatus is SUCCESS and every property is
    left byte-for-byte unchanged (not silently coerced, not partially applied)."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    queue_name = ctx.unique_name("sim2real-behav-ccpatch-")
    create_progress = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps(
            {
                "QueueName": queue_name,
                "DelaySeconds": 0,
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            }
        ),
    )["ProgressEvent"]
    ctx.on_cleanup(
        lambda: sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=queue_name)["QueueUrl"])
    )
    create_final = _poll_request_status(ctx, create_progress["RequestToken"])
    assert create_final["OperationStatus"] == "SUCCESS", (
        f"expected SUCCESS creating the queue, got {create_final}"
    )

    before_props = json.loads(
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_name)["ResourceDescription"][
            "Properties"
        ]
    )

    update_progress = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=queue_name, PatchDocument="[]"
    )["ProgressEvent"]
    async_final = _poll_request_status(ctx, update_progress["RequestToken"])
    assert async_final["OperationStatus"] == "SUCCESS", f"unexpected final status: {async_final}"

    # Effect: the resource's properties are byte-for-byte unchanged by the no-op.
    after_props = json.loads(
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_name)["ResourceDescription"][
            "Properties"
        ]
    )
    assert after_props == before_props, f"no-op patch mutated state: {before_props} -> {after_props}"

    # Positive control: a real, non-empty patch is accepted and actually applied,
    # distinguishing the no-op path above from a handler that just ignores patches.
    real_patch = json.dumps([{"op": "replace", "path": "/DelaySeconds", "value": 30}])
    update_progress = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=queue_name, PatchDocument=real_patch
    )["ProgressEvent"]
    update_final = _poll_request_status(ctx, update_progress["RequestToken"])
    assert update_final["OperationStatus"] == "SUCCESS", (
        f"expected SUCCESS applying the real patch, got {update_final}"
    )

    updated_props = json.loads(
        cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=queue_name)["ResourceDescription"][
            "Properties"
        ]
    )
    assert updated_props["DelaySeconds"] == 30, (
        f"expected DelaySeconds=30 after the real patch, got {updated_props.get('DelaySeconds')!r}"
    )


def _poll_request_status(ctx, token, timeout_s=120.0, interval_s=3.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} never reached a terminal status; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
