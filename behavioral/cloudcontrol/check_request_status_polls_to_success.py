"""request-status-polls-to-success."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _wait_terminal(cc, request_token, timeout_s=90, interval_s=2):
    """Poll GetResourceRequestStatus until the request reaches a terminal
    OperationStatus. Returns the final ProgressEvent dict."""
    holder = {}

    def probe():
        resp = cc.get_resource_request_status(RequestToken=request_token)
        holder["event"] = resp["ProgressEvent"]
        return holder["event"]

    _poll_until(
        probe,
        lambda e: e is not None and e.get("OperationStatus") in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return holder["event"]

def _delete_quiet(cc, type_name, identifier):
    try:
        resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
        _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60, interval_s=2)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise

def _track(cc, ctx, type_name, identifier):
    ctx.on_cleanup(lambda: _delete_quiet(cc, type_name, identifier))

def _ssm_desired_state(name, value="v1", ptype="String", tag_value=""):
    return json.dumps({
        "Name": name, "Type": ptype, "Value": value,
        "Tags": {"sim2real": tag_value},
    })

CHECK = "request-status-polls-to-success"
GROUP = 'lifecycle'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus transitions from a non-terminal/observed status to a terminal SUCCESS with matching RequestToken."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-cc-param-")
    value = "v1"
    resp = cc.create_resource(
        TypeName=SSM_PARAM_TYPE, DesiredState=_ssm_desired_state(name, value=value, tag_value=CHECK)
    )
    token = resp["ProgressEvent"]["RequestToken"]
    _track(cc, ctx, SSM_PARAM_TYPE, name)

    event = _wait_terminal(cc, token)
    assert event["OperationStatus"] == "SUCCESS", f"unexpected terminal status: {event}"
    assert event["RequestToken"] == token, (
        f"terminal ProgressEvent RequestToken {event['RequestToken']!r} does not match the token "
        f"{token!r} the request was created with"
    )
    assert event["TypeName"] == SSM_PARAM_TYPE, (
        f"terminal ProgressEvent TypeName {event['TypeName']!r}, expected {SSM_PARAM_TYPE!r}"
    )
    assert event["Identifier"] == name, (
        f"terminal ProgressEvent Identifier {event['Identifier']!r}, expected {name!r}"
    )

    # The status poll alone cannot tell a real create from a tracker that only ever fakes
    # SUCCESS: an independent read at the native destination proves the resource is real.
    param = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert param["Value"] == value, (
        f"SSM holds Value {param['Value']!r} for {name!r}, expected {value!r} -- the terminal "
        "SUCCESS status did not correspond to a real write"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
