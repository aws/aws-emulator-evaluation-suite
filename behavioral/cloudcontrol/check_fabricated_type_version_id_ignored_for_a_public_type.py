"""fabricated-type-version-id-ignored-for-a-public-type."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fabricated-type-version-id-ignored-for-a-public-type"
GROUP = "representation"
SERVICES = ["cloudcontrol"]

SSM_PARAM_TYPE = "AWS::SSM::Parameter"
TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
# Well-formed per the modelled TypeVersionId pattern ^[A-Za-z0-9-]+$, and registered for nothing.
FABRICATED_VERSION = "00000099"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateResource on public AWS::SSM::Parameter with an unregistered TypeVersionId succeeds and
    really writes the parameter, as seen by SSM and GetResource; TypeVersionId is for private types.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_CreateResource.html
    """
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")

    # Control: the identical request without TypeVersionId, before and after the fabricated one.
    control_name = ctx.unique_name("sim2real-behav-ccver-ctl-")
    control = cc.create_resource(
        TypeName=SSM_PARAM_TYPE, DesiredState=_desired_state(control_name)
    )
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, control_name))
    control_event = _wait_terminal(cc, control["ProgressEvent"]["RequestToken"])
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"the positive control create (no TypeVersionId) terminated "
        f"{control_event['OperationStatus']!r} with ErrorCode "
        f"{control_event.get('ErrorCode')!r}; without a working control the fabricated-version "
        f"call below cannot be attributed to TypeVersionId specifically"
    )
    assert ssm.get_parameter(Name=control_name)["Parameter"]["Value"] == control_name, (
        f"the control parameter {control_name!r} is not readable from SSM with the value the "
        f"desired state asked for"
    )

    ignored_name = ctx.unique_name("sim2real-behav-ccver-ign-")
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, ignored_name))
    ignored = cc.create_resource(
        TypeName=SSM_PARAM_TYPE,
        DesiredState=_desired_state(ignored_name),
        TypeVersionId=FABRICATED_VERSION,
    )
    ignored_event = _wait_terminal(cc, ignored["ProgressEvent"]["RequestToken"])
    assert ignored_event["OperationStatus"] == "SUCCESS", (
        f"CreateResource carrying TypeVersionId={FABRICATED_VERSION!r} -- a version registered "
        f"for nothing -- terminated {ignored_event['OperationStatus']!r} with ErrorCode "
        f"{ignored_event.get('ErrorCode')!r}; real AWS ignores TypeVersionId for a PUBLIC type "
        f"and succeeds, so refusing it here is a divergence from the measured contract, not a "
        f"stricter emulation of it"
    )
    assert ignored_event["Identifier"] == ignored_name, (
        f"Cloud Control reports identifier {ignored_event['Identifier']!r}, expected "
        f"{ignored_name!r}"
    )

    param = ssm.get_parameter(Name=ignored_name)["Parameter"]
    assert param["Value"] == ignored_name, (
        f"SSM holds Value {param['Value']!r} for {ignored_name!r}, expected the name itself; a "
        f"target that faked SUCCESS without really writing SSM would fail here"
    )

    matched = _describe_names(ssm, ignored_name)
    assert matched == [ignored_name], (
        f"ssm:DescribeParameters reports {matched!r} for {ignored_name!r}; the parameter "
        f"created alongside a fabricated TypeVersionId must be genuinely visible there too, not "
        f"only through the one read path this check happened to try first"
    )

    cc_props = json.loads(
        cc.get_resource(TypeName=SSM_PARAM_TYPE, Identifier=ignored_name)[
            "ResourceDescription"
        ]["Properties"]
    )
    assert cc_props["Value"] == param["Value"], (
        f"Cloud Control reports Value {cc_props['Value']!r} for {ignored_name!r} but SSM "
        f"reports {param['Value']!r}; the two planes must describe the same write"
    )

    ssm.delete_parameter(Name=ignored_name)
    absent_code, absent_message = _error(lambda: ssm.get_parameter(Name=ignored_name))
    assert absent_code == "ParameterNotFound", (
        f"SSM answers {absent_code!r} for the deleted {ignored_name!r}, expected "
        f"ParameterNotFound"
    )
    assert absent_message == "", (
        f"SSM's ParameterNotFound carries an empty message, got {absent_message!r}"
    )
    # message varies: the handler embeds its own per-call RequestToken, which the check never sees
    cc_code, _ = _error(
        lambda: cc.get_resource(TypeName=SSM_PARAM_TYPE, Identifier=ignored_name)
    )
    assert cc_code == "ResourceNotFoundException", (
        f"Cloud Control GetResource answers {cc_code!r} for the deleted {ignored_name!r}, "
        f"expected ResourceNotFoundException"
    )

    after_name = ctx.unique_name("sim2real-behav-ccver-after-")
    ctx.on_cleanup(lambda: _delete_parameter_quiet(ssm, after_name))
    after = cc.create_resource(TypeName=SSM_PARAM_TYPE, DesiredState=_desired_state(after_name))
    after_event = _wait_terminal(cc, after["ProgressEvent"]["RequestToken"])
    assert after_event["OperationStatus"] == "SUCCESS", (
        f"an identical create with no TypeVersionId, issued after the fabricated-version create, "
        f"terminated {after_event['OperationStatus']!r} with ErrorCode "
        f"{after_event.get('ErrorCode')!r}; the earlier call must not have left the wiring in a "
        f"bad state"
    )
    assert ssm.get_parameter(Name=after_name)["Parameter"]["Value"] == after_name, (
        f"the post-test parameter {after_name!r} is not readable from SSM"
    )


def _desired_state(name: str) -> str:
    """The Value is the name so every parameter's read-back is self-identifying."""
    return json.dumps(
        {"Name": name, "Type": "String", "Value": name, "Tags": {"sim2real": CHECK}}
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"waited {timeout_s}s for {reason} and it never happened; last observation {last!r}"
    )


def _wait_terminal(cc, request_token, *, timeout_s=90.0, interval_s=2.0):
    """Poll GetResourceRequestStatus to a terminal OperationStatus; return the ProgressEvent."""
    return _poll_until(
        lambda: cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"],
        lambda event: event is not None and event["OperationStatus"] in TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        reason=f"request {request_token} to reach a terminal OperationStatus",
    )


def _error(fn):
    """The AWS (code, message) raised by fn(). RAISES if the call unexpectedly SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _describe_names(ssm, name):
    """Names DescribeParameters returns for an exact name, a read path besides GetParameter."""
    found = []
    paginator = ssm.get_paginator("describe_parameters")
    for page in paginator.paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ):
        found.extend(p["Name"] for p in page["Parameters"])
    return found


def _delete_parameter_quiet(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
