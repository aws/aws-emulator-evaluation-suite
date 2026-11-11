"""request-status-monotonic-transition-timing."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "request-status-monotonic-transition-timing"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudcontrol"]

_TYPE_NAME = "AWS::SQS::Queue"
_RANK = {
    "PENDING": 0,
    "IN_PROGRESS": 1,
    "CANCEL_IN_PROGRESS": 1,
    "SUCCESS": 2,
    "FAILED": 2,
    "CANCEL_COMPLETE": 2,
}


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An SQS queue create through Cloud Control answers a non-terminal PENDING/IN_PROGRESS
    ProgressEvent, and polling it shows a monotonic sequence to SUCCESS; the status never regresses."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-mono-")

    start = time.monotonic()
    resp = cc.create_resource(
        TypeName=_TYPE_NAME,
        DesiredState=json.dumps(
            {"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ),
    )
    token = resp["ProgressEvent"]["RequestToken"]

    # The create's own ProgressEvent is the first observation: the request is asynchronous, so it
    # is non-terminal whatever the polls that follow read.
    observed = [resp["ProgressEvent"]["OperationStatus"]]
    identifier = None
    deadline = start + 180.0
    while time.monotonic() < deadline:
        pe = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        status = pe["OperationStatus"]
        observed.append(status)
        if status in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            identifier = pe.get("Identifier")
            break
        time.sleep(1.5)
    else:
        raise AssertionError(f"request never reached a terminal state; observed={observed}")
    elapsed_s = time.monotonic() - start

    if identifier:
        ctx.on_cleanup(lambda: _cleanup_delete(cc, _TYPE_NAME, identifier))

    ranks = [_RANK[s] for s in observed]
    for i in range(1, len(ranks)):
        assert ranks[i] >= ranks[i - 1], (
            f"OperationStatus regressed from {observed[i - 1]} to {observed[i]} "
            f"(full sequence: {observed})"
        )

    assert observed[-1] == "SUCCESS", f"expected the create to terminate SUCCESS, got {observed[-1]}"

    assert observed[0] in ("PENDING", "IN_PROGRESS"), (
        f"CreateResource answered {observed[0]!r} after {elapsed_s:.1f}s; Cloud Control "
        f"orchestration for {_TYPE_NAME} is asynchronous, so the create answers a non-terminal "
        f"PENDING/IN_PROGRESS event (observed={observed})"
    )


def _cleanup_delete(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        deadline = time.monotonic() + 180.0
        token = resp["ProgressEvent"]["RequestToken"]
        pe = resp["ProgressEvent"]
        while time.monotonic() < deadline:
            pe = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
            if pe["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
                break
            time.sleep(1.5)
        if pe["OperationStatus"] != "SUCCESS":
            raise AssertionError(f"teardown: deleting queue {identifier} ended {pe!r}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
