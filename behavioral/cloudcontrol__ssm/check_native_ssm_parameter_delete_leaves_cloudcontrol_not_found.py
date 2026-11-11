"""native-ssm-parameter-delete-leaves-cloudcontrol-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "native-ssm-parameter-delete-leaves-cloudcontrol-not-found"
GROUP = "native-truth"
SERVICES = ["cloudcontrol", "ssm"]

PARAM_TYPE = "AWS::SSM::Parameter"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A parameter created with SSM's own API is visible to Cloud Control with SSM's values, and
    once SSM itself deletes it Cloud Control GetResource answers ResourceNotFoundException with
    the handler's exact not-found message, not a stale success.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/resource-operations.html
    """
    cc = ctx.client("cloudcontrol")
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-ccnat-")

    ssm.put_parameter(
        Name=name, Value="native-original", Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=name), "ParameterNotFound"))
    native = ssm.get_parameter(Name=name)["Parameter"]

    # ---- Cloud Control resolves a parameter it never created, with SSM's own values --------------
    described = _poll_until(
        lambda: _get_resource_or_none(cc, name),
        lambda desc: desc is not None,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to resolve {name!r}, a parameter it never created",
    )
    assert described["Identifier"] == name, (
        f"GetResource echoed Identifier {described['Identifier']!r}, expected {name!r}"
    )
    props = json.loads(described["Properties"])
    assert props.get("Name") == name, (
        f"Cloud Control reports Name {props.get('Name')!r}, expected {name!r}"
    )
    assert props.get("Value") == "native-original", (
        f"Cloud Control reports Value {props.get('Value')!r}, SSM reports {native['Value']!r}"
    )
    assert props.get("Type") == "String", (
        f"Cloud Control reports Type {props.get('Type')!r}, expected 'String'"
    )
    assert props.get("Arn") == native["ARN"], (
        f"Cloud Control reports Arn {props.get('Arn')!r}, SSM reports {native['ARN']!r}"
    )

    # ---- ListResources enumerates it, paginated -----------------------------------------------
    _poll_until(
        lambda: _list_all_parameter_names(cc),
        lambda names: name in names,
        timeout_s=30.0,
        interval_s=2.0,
        reason=f"ListResources to enumerate {name!r}, a parameter Cloud Control never created",
    )

    # ---- break the one thing: SSM itself deletes the parameter, not Cloud Control ------------------
    ssm.delete_parameter(Name=name)
    native_gone = _error(lambda: ssm.get_parameter(Name=name))
    assert native_gone == ("ParameterNotFound", ""), (
        f"GetParameter of the natively-deleted parameter {name!r} answered {native_gone!r}, "
        f"expected ('ParameterNotFound', '')"
    )

    # ---- the effect: Cloud Control must stop vouching for a parameter SSM has deleted -----------
    cc_error = _poll_for_client_error(
        lambda: cc.get_resource(TypeName=PARAM_TYPE, Identifier=name),
        timeout_s=45.0,
        interval_s=2.0,
        reason=f"Cloud Control GetResource to report {name!r} gone after the native delete",
    )
    expected_message = _handler_not_found(
        cc_error[1],
        f"AWS::SSM::Parameter Handler returned status FAILED: Resource of type "
        f"'AWS::SSM::Parameter' with identifier '{name}' was not found.",
    )
    assert cc_error == ("ResourceNotFoundException", expected_message), (
        f"GetResource for the natively-deleted parameter {name!r} answered {cc_error!r}, expected "
        f"('ResourceNotFoundException', {expected_message!r}); a target that still serves it is "
        f"over-permissive"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, reason):
    """Bounded retry with a deadline and a stated reason. RAISES on timeout."""
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


def _get_resource_or_none(cc, name):
    try:
        return cc.get_resource(TypeName=PARAM_TYPE, Identifier=name)["ResourceDescription"]
    except ClientError:
        return None


def _list_all_parameter_names(cc):
    """Every identifier ListResources reports for AWS::SSM::Parameter, across pages."""
    found: set[str] = set()
    kwargs = {"TypeName": PARAM_TYPE}
    for _ in range(500):
        resp = cc.list_resources(**kwargs)
        found.update(d["Identifier"] for d in resp.get("ResourceDescriptions", []))
        token = resp.get("NextToken")
        if not token:
            return found
        kwargs["NextToken"] = token
    raise AssertionError(
        f"ListResources for {PARAM_TYPE} still returned a NextToken after 500 pages "
        f"({len(found)} identifiers); pagination is not terminating"
    )


def _error(fn):
    """The AWS error (code, message) raised by fn(); raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _poll_for_client_error(fn, *, timeout_s, interval_s, reason):
    """Poll fn() until it raises ClientError and return its (Error.Code, Error.Message). RAISES
    when fn() is still succeeding at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason} and it never happened; last result {result!r}"
            )
        time.sleep(interval_s)


def _handler_not_found(message, detail):
    """Whether message is the handler's NotFound refusal; its trailing RequestToken is server-chosen."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
