"""unicode-property-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unicode-property-round-trip"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A multi-byte unicode tag value set via CreateResource reads back unchanged from GetResource
    and from SQS's own ListQueueTags, since Cloud Control's echo alone does not prove the native
    tag store received it intact."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")

    # Tag values allow only unicode letters, digits, whitespace and _ . : / = + - @;
    # SQS rejects emoji/symbols with GeneralServiceException, so use letters across scripts.
    unicode_value = "こんにちは-世界-Ünïcödé-Тест-يونيكود"
    queue_name = ctx.unique_name("sim2real-cc-uni-")
    desired_state = json.dumps(
        {
            "QueueName": queue_name,
            "Tags": [
                {"Key": "lang-sample", "Value": unicode_value},
                {"Key": "sim2real", "Value": CHECK},
            ],
        }
    )
    create_resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)
    event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    queue_url = event["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(cc, queue_url))

    props = _get_properties(cc, "AWS::SQS::Queue", queue_url)
    cc_tags = {t["Key"]: t["Value"] for t in props.get("Tags", [])}
    assert cc_tags.get("lang-sample") == unicode_value, (
        f"Cloud Control's own GetResource mangled the unicode tag: expected {unicode_value!r}, "
        f"got {cc_tags.get('lang-sample')!r}"
    )

    native_tags = sqs.list_queue_tags(QueueUrl=queue_url).get("Tags", {})
    assert native_tags.get("lang-sample") == unicode_value, (
        f"SQS's own ListQueueTags reports {native_tags.get('lang-sample')!r} for a tag Cloud "
        f"Control's DesiredState declared as {unicode_value!r} -- Cloud Control's own echo can "
        "look correct while the translation to the native tag store still mangles it"
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
