"""unicode-property-value-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unicode-property-value-round-trip"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An SSM parameter value containing an emoji, a decomposed combining-character sequence, and CJK text
    round-trips byte-identical through CreateResource/GetResource -- no normalization or mangling."""
    cc = ctx.client("cloudcontrol")
    param_name = ctx.unique_name("sim2real-behav-cc-uni-")
    # precomposed e-acute, then e + COMBINING ACUTE ACCENT (distinct codepoints), an emoji, and katakana.
    unicode_value = "caf\u00e9 e\u0301 \U0001f389 \u30c6\u30b9\u30c8"
    desired_state = json.dumps(
        {"Name": param_name, "Type": "String", "Value": unicode_value, "Tags": {"sim2real": CHECK}}
    )
    resp = cc.create_resource(TypeName="AWS::SSM::Parameter", DesiredState=desired_state)
    event = _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    identifier = event["Identifier"]
    ctx.on_cleanup(lambda: _delete_and_wait(ctx, identifier))

    got = cc.get_resource(TypeName="AWS::SSM::Parameter", Identifier=identifier)
    props = json.loads(got["ResourceDescription"]["Properties"])
    assert props["Value"] == unicode_value, props["Value"]


def _wait_for_progress(ctx, request_token, timeout_s=180.0, interval_s=2.0):
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    event = None
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return event
        time.sleep(interval_s)
    raise AssertionError(f"operation did not stabilize within {timeout_s}s, last event={event}")


def _delete_and_wait(ctx, identifier, type_name="AWS::SSM::Parameter"):
    cc = ctx.client("cloudcontrol")
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    try:
        _wait_for_progress(ctx, resp["ProgressEvent"]["RequestToken"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RequestTokenNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
