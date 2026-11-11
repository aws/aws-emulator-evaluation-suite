"""empty-vs-absent-property-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-vs-absent-property-preserved"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicitly empty-string tag value is preserved and returned as a present, empty
    string -- distinguishable from a sibling top-level property that was never specified at
    all and must be entirely absent from the returned Properties."""
    cc = ctx.client("cloudcontrol")

    queue_name = ctx.unique_name("sim2real-cc-emptyabs-")
    desired_state = json.dumps(
        {"QueueName": queue_name, "Tags": [{"Key": "present-empty", "Value": ""}]}
    )
    create_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    queue_url = event["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, queue_url))

    props = _get_properties(cc, "AWS::SQS::Queue", queue_url)

    tags_by_key = {t["Key"]: t for t in props.get("Tags", [])}
    assert "present-empty" in tags_by_key, "explicitly-set empty tag disappeared entirely"
    tag_entry = tags_by_key["present-empty"]
    assert "Value" in tag_entry, "empty string value was dropped instead of preserved as ''"
    assert tag_entry["Value"] == "", f"expected empty string, got {tag_entry['Value']!r}"

    # A property we never specified at all must be entirely absent, not present as null/"".
    assert "KmsMasterKeyId" not in props, (
        f"never-specified KmsMasterKeyId leaked into Properties as {props.get('KmsMasterKeyId')!r}"
    )


def _wait_for_progress(cc, request_token: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state; last={last}")


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


def _best_effort_delete(cc, queue_url: str) -> None:
    try:
        resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=queue_url)
        _wait_for_progress(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60)
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
