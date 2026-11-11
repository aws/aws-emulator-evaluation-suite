"""update-patch-add-then-remove-property."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-patch-add-then-remove-property"
GROUP = "state-machine"
SERVICES = ["cloudcontrol"]

_SNS_TOPIC = "AWS::SNS::Topic"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """JSON Patch add then remove on a mutable property is applied and reverted correctly."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-behav-cc-topic-")

    final = _create_and_wait(
        ctx, cc, _SNS_TOPIC,
        {"TopicName": name, "Tags": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    assert final["OperationStatus"] == "SUCCESS", final
    identifier = final["Identifier"]

    add_result = _update_and_wait(
        cc,
        _SNS_TOPIC,
        identifier,
        [{"op": "add", "path": "/DisplayName", "value": "cc-fidelity-check"}],
    )
    assert add_result["OperationStatus"] == "SUCCESS", add_result
    props_after_add = _get_properties(cc, _SNS_TOPIC, identifier)
    assert props_after_add.get("DisplayName") == "cc-fidelity-check", props_after_add

    remove_result = _update_and_wait(
        cc,
        _SNS_TOPIC,
        identifier,
        [{"op": "remove", "path": "/DisplayName"}],
    )
    assert remove_result["OperationStatus"] == "SUCCESS", remove_result
    props_after_remove = _get_properties(cc, _SNS_TOPIC, identifier)
    assert not props_after_remove.get("DisplayName"), props_after_remove

    _delete_and_wait(cc, _SNS_TOPIC, identifier)


_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_for_request(cc, request_token: str, timeout_s: float = 60, interval_s: float = 2) -> dict:
    """Poll GetResourceRequestStatus until a terminal OperationStatus is reached."""

    def probe():
        return cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]

    return _poll_until(
        probe,
        lambda ev: ev.get("OperationStatus") in _TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} to reach a terminal state",
    )


def _cleanup_delete(cc, type_name: str, identifier: str) -> None:
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=45, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _create_and_wait(ctx, cc, type_name: str, desired_state: dict, timeout_s: float = 60) -> dict:
    """CreateResource + poll to terminal; registers teardown for a successful create."""
    resp = cc.create_resource(TypeName=type_name, DesiredState=json.dumps(desired_state))
    final = _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=timeout_s)
    if final.get("OperationStatus") == "SUCCESS" and final.get("Identifier"):
        identifier = final["Identifier"]
        ctx.on_cleanup(lambda: _cleanup_delete(cc, type_name, identifier))
    return final


def _update_and_wait(cc, type_name: str, identifier: str, patch_document: list, timeout_s: float = 60) -> dict:
    resp = cc.update_resource(
        TypeName=type_name, Identifier=identifier, PatchDocument=json.dumps(patch_document)
    )
    return _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=timeout_s)


def _delete_and_wait(cc, type_name: str, identifier: str, timeout_s: float = 60) -> dict:
    resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    return _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=timeout_s)


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    """GetResource and return the Properties dict (parsed JSON)."""
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    props = resp["ResourceDescription"]["Properties"]
    return json.loads(props) if isinstance(props, str) else props


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
