"""cloudcontrol-create-ssm-parameter-visible-to-native-ssm-getparameter."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-create-ssm-parameter-visible-to-native-ssm-getparameter"
GROUP = 'native-truth'
SERVICES = ['cloudcontrol']
SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
VALUE = "hello-from-cloudcontrol"


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


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A Cloud Control CreateResource of an AWS::SSM::Parameter is visible through SSM itself:
    GetParameter returns its Value, Type String and Version 1, the history holds that one version, and
    GetResource reports the same Value and ARN."""
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-ccnative-")

    resp = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=json.dumps({
            "Name": name, "Type": "String", "Value": VALUE,
            "Tags": {"sim2real": CHECK},
        }),
    )
    # Registered before the first assertion: a FAILED terminal event can still have written the
    # parameter, and the SSM name is the only handle cleanup can delete it by, not the Cloud Control token.
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, name))
    event = _wait_terminal(cc, resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", f"create did not succeed: {event!r}"
    assert event["Identifier"] == name, (
        f"Cloud Control reports identifier {event['Identifier']!r}, the desired state asked for "
        f"{name!r}"
    )

    param = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert param["Value"] == VALUE, f"SSM holds Value {param['Value']!r}, expected {VALUE!r}"
    assert param["Type"] == "String", f"SSM holds Type {param['Type']!r}, expected 'String'"
    assert param["Version"] == 1, (
        f"SSM reports Version {param['Version']!r}; a single CreateResource must leave the native "
        "parameter at version 1"
    )

    history = []
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        history.extend((h["Version"], h["Value"]) for h in page["Parameters"])
    assert history == [(1, VALUE)], (
        f"SSM parameter history is {history!r}; one CreateResource must produce exactly one entry"
    )

    props = json.loads(
        cc.get_resource(TypeName=SSM_PARAM_TYPE, Identifier=name)["ResourceDescription"]["Properties"]
    )
    assert props["Value"] == param["Value"], (
        f"Cloud Control reports Value {props['Value']!r} but SSM reports {param['Value']!r}"
    )
    assert props["Arn"] == param["ARN"], (
        f"Cloud Control reports Arn {props['Arn']!r} but SSM reports {param['ARN']!r}, so the two "
        "services are not describing the same resource"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
