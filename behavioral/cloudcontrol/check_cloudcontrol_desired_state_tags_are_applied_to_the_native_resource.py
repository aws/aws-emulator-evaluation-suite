"""cloudcontrol-desired-state-tags-are-applied-to-the-native-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-desired-state-tags-are-applied-to-the-native-resource"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
WAVE = "ga-depth"


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_terminal(cc, request_token, *, timeout_s=120, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} reaching a terminal OperationStatus",
    )


def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _native_tags(ssm, name):
    return {t["Key"]: t["Value"] for t in
            ssm.list_tags_for_resource(ResourceType="Parameter", ResourceId=name)["TagList"]}


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """Both DesiredState tags of an AWS::SSM::Parameter are readable through SSM's
    ListTagsForResource, and a JSON Patch remove of /Tags/wave deletes that tag natively and leaves
    the other, which GetResource also reports."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-cctag-")

    created = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({
            "Name": name, "Type": "String", "Value": "tagged",
            "Tags": {"sim2real": CHECK, "wave": WAVE},
        }),
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    create_event = _wait_terminal(cc, created["ProgressEvent"]["RequestToken"])
    assert create_event["OperationStatus"] == "SUCCESS", f"create did not succeed: {create_event!r}"

    before = _native_tags(ssm, name)
    assert before == {"sim2real": CHECK, "wave": WAVE}, (
        f"SSM's own tagging API reports {before!r}; the DesiredState declared both tags"
    )

    patched = cc.update_resource(
        TypeName=SSM_PARAM_TYPE, Identifier=name,
        PatchDocument=json.dumps([{"op": "remove", "path": "/Tags/wave"}]),
    )
    update_event = _wait_terminal(cc, patched["ProgressEvent"]["RequestToken"])
    assert update_event["OperationStatus"] == "SUCCESS", f"tag removal failed: {update_event!r}"

    after = _native_tags(ssm, name)
    assert after == {"sim2real": CHECK}, (
        f"SSM's own tagging API reports {after!r} after removing /Tags/wave; the tag was not "
        "removed natively, or the surviving tag was collateral damage"
    )

    props = json.loads(
        cc.get_resource(TypeName=SSM_PARAM_TYPE, Identifier=name)["ResourceDescription"]["Properties"]
    )
    assert props["Tags"] == after, (
        f"Cloud Control reports Tags {props['Tags']!r} but SSM reports {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
