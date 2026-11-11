"""sam-invalid-document-error-taxonomy-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sam-invalid-document-error-taxonomy-rejected"

GROUP = "deploy-sam-transform"

SERVICES = ["apigateway", "cloudformation", "lambda"]

# The banner the SAM validator puts in front of every aggregated diagnostic, and the wrapper
# CloudFormation adds around it.
_SAM_BANNER = "Invalid Serverless Application Specification document."

_CFN_WRAPPER = "Transform AWS::Serverless-2016-10-31 failed with:"

# One cause per fault, each naming the offending resource and property.
_CAUSES = {
    "bad_policy_name": (
        "Resource with id [Fn] is invalid. Policy at index 0 in the 'Policies' property is not valid"
    ),
    "missing_handler": (
        "Resource with id [Fn] is invalid. Runtime and Handler needs to be present when "
        "PackageType is of type `Zip`"
    ),
    "bogus_event_type": (
        "Resource with id [Fn] is invalid. Event with id [Ev] is invalid. Resource dict has missing "
        "or invalid value for key Type. Event Type is: NotARealEventType."
    ),
    "simpletable_no_key_type": (
        "Resource with id [Fn] is invalid. Property 'PrimaryKey.Type' is required."
    ),
    "two_faults": (
        "Resource with id [Fn] is invalid. Policy at index 0 in the 'Policies' property is not valid "
        "Resource with id [Other] is invalid. Runtime and Handler needs to be present when PackageType "
        "is of type `Zip`"
    ),
}


def _sam_reason(label: str) -> str:
    """The whole StatusReason the transform reports for one faulty document."""
    count = 2 if label == "two_faults" else 1
    return f"{_CFN_WRAPPER} {_SAM_BANNER} Number of errors found: {count}. {_CAUSES[label]}"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """Invalid SAM documents each fail the change set with the exact per-cause SAM diagnostic and
    materialise nothing; an unknown Serverless type gets CloudFormation's own format error instead.

    Reference: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification.html
    """
    cfn = ctx.client("cloudformation")
    awslambda = ctx.client("lambda")

    reasons: dict[str, str] = {}

    for label in ("bad_policy_name", "missing_handler", "bogus_event_type",
                  "simpletable_no_key_type", "two_faults"):
        fn_name = _xname(ctx, f"sam-bad-{label.replace('_', '-')}")
        described, stack_name = _failed_change_set(ctx, _bad_template(label, fn_name), label)
        reason = described.get("StatusReason") or ""
        reasons[label] = reason

        assert described["Status"] == "FAILED", (
            f"leg {label}: an invalid SAM document must fail the change set, not reach "
            f"{described['Status']!r}"
        )
        want_reason = _sam_reason(label)
        assert reason == want_reason, (
            f"leg {label}: expected the SAM validator's exact per-cause diagnostic "
            f"{want_reason!r}, got {reason!r}"
        )

        # A failed transform leaves the shell stack at REVIEW_IN_PROGRESS with nothing created.
        assert described.get("Changes") == [], (
            f"leg {label}: a failed transform yields no change list; got {described.get('Changes')!r}"
        )
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        assert status == "REVIEW_IN_PROGRESS", (
            f"leg {label}: the shell stack must stay unmaterialised at REVIEW_IN_PROGRESS; got "
            f"{status!r}"
        )
        assert not _stack_named(cfn, stack_name, ["CREATE_IN_PROGRESS", "CREATE_COMPLETE"]), (
            f"leg {label}: {stack_name!r} must not appear among created stacks"
        )
        code, message = _error(lambda n=fn_name: awslambda.get_function(FunctionName=n))
        assert code == "ResourceNotFoundException", (
            f"leg {label}: no partial expansion may be materialised -- the function the template "
            f"would have created must not exist; got {code!r}"
        )
        want_message = (
            f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}"
        )
        assert message == want_message, (
            f"leg {label}: expected not-found message {want_message!r}, got {message!r}"
        )

    contrast_fn = _xname(ctx, "sam-bad-unknown-type")
    described, stack_name = _failed_change_set(
        ctx, _bad_template("unknown_serverless_type", contrast_fn), "unknown_serverless_type"
    )
    contrast_reason = described.get("StatusReason") or ""
    reasons["unknown_serverless_type"] = contrast_reason
    assert described["Status"] == "FAILED", (
        f"an unrecognised AWS::Serverless::* type must fail; got {described['Status']!r}"
    )
    want_contrast = (
        "Template format error: Unrecognized resource types: [AWS::Serverless::NotAThing]"
    )
    assert contrast_reason == want_contrast, (
        "an unrecognised resource type is CloudFormation's error, not the SAM validator's -- an "
        f"emulator that funnels everything through one message fails here. Expected "
        f"{want_contrast!r}, got {contrast_reason!r}"
    )

    assert len(set(reasons.values())) == len(reasons), (
        "every fault must produce its own diagnostic; these six reasons collapse to "
        f"{len(set(reasons.values()))} distinct strings: {reasons!r}"
    )

    control_fn = _xname(ctx, "sam-control-fn")
    control_template = _base_template(control_fn)
    control = _create_change_set(ctx, control_template)
    assert control["Status"] == "CREATE_COMPLETE", (
        "control: the fault-free base document -- byte-identical to the missing_handler leg "
        "except for the one Handler line -- must be accepted. Got "
        f"{control['Status']!r} / {control.get('StatusReason')!r}"
    )
    assert control["ExecutionStatus"] == "AVAILABLE", (
        f"control: change set must be executable; got {control['ExecutionStatus']!r}"
    )
    planned = sorted(c["ResourceChange"]["LogicalResourceId"] for c in control["Changes"])
    assert planned == ["Fn", "FnRole"], (
        f"control: the transform must plan the function and a synthesized role; got {planned!r}"
    )
    _execute_change_set(ctx, control["stack_name"], control["change_set_name"])
    ctx.on_cleanup(
        lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{control_fn}")
    )
    response = awslambda.invoke(FunctionName=control_fn, InvocationType="RequestResponse",
                                Payload=b"{}")
    payload = response["Payload"].read().decode()
    assert not response.get("FunctionError"), (
        f"control: the accepted document's function must run; got {payload[:300]!r}"
    )
    assert json.loads(payload) == "ok", f"control: function returned {payload[:200]!r}"

    original = _template_body(cfn, control["stack_name"], "Original")
    processed = _template_body(cfn, control["stack_name"], "Processed")
    assert "AWS::Serverless::Function" in json.dumps(original), (
        "control: the Original projection must be the body as submitted"
    )
    assert "AWS::IAM::Role" not in json.dumps(original), (
        "control: the Original projection must not contain the synthesized role"
    )
    assert "AWS::IAM::Role" in json.dumps(processed), (
        "control: the Processed projection must contain the synthesized role"
    )

    # A change set IS the review AUTO_EXPAND exists to force, so the change-set path does not
    # require it; create_stack, which expands inline, does.
    gate_fn = _xname(ctx, "sam-gate-fn")
    gate_stack = _xname(ctx, "stk")
    code, message = _error(lambda: cfn.create_stack(
        StackName=gate_stack,
        TemplateBody=_base_template(gate_fn),
        Capabilities=["CAPABILITY_IAM"],
    ))
    assert code == "InsufficientCapabilitiesException", (
        f"create_stack expands the transform inline and must demand CAPABILITY_AUTO_EXPAND; "
        f"got {code!r}"
    )
    assert message == "Requires capabilities : [CAPABILITY_AUTO_EXPAND]", (
        f"expected the exact capability refusal, got {message!r}"
    )
    assert not _stack_named(cfn, gate_stack, ["CREATE_IN_PROGRESS", "CREATE_COMPLETE",
                                              "REVIEW_IN_PROGRESS"]), (
        f"the refused create_stack must have created nothing; {gate_stack!r} exists"
    )
    reviewed = _create_change_set(ctx, _base_template(gate_fn),
                                  capabilities=["CAPABILITY_IAM"])
    assert reviewed["Status"] == "CREATE_COMPLETE", (
        "the same body via create_change_set must be accepted WITHOUT CAPABILITY_AUTO_EXPAND -- "
        "the capability requirement is deferred to execution, not applied at review. Got "
        f"{reviewed['Status']!r} / {reviewed.get('StatusReason')!r}"
    )
    assert sorted(
        c["ResourceChange"]["LogicalResourceId"] for c in reviewed["Changes"]
    ) == ["Fn", "FnRole"], (
        "the un-capability-ed change set must still show the expanded plan; got "
        f"{reviewed['Changes']!r}"
    )



_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"

_OK_CODE = "def handler(event, context):\n    return 'ok'\n"


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": _MANAGED_TAG_KEY, "Value": "true"},
            {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")}]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _base_template(function_name: str) -> str:
    """The fault-free document every negative leg is one edit away from."""
    return json.dumps({
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {"Fn": {"Type": "AWS::Serverless::Function", "Properties": {
            "FunctionName": function_name,
            "Handler": "index.handler",
            "Runtime": "python3.12",
            "InlineCode": _OK_CODE,
            "Policies": [{"DynamoDBCrudPolicy": {"TableName": "sim2real-xsvc-nonexistent"}}],
        }}},
    })


def _bad_template(label: str, function_name: str) -> str:
    """The base document with exactly one fault introduced (two for `two_faults`)."""
    template = json.loads(_base_template(function_name))
    props = template["Resources"]["Fn"]["Properties"]
    if label == "bad_policy_name":
        props["Policies"] = [{"NoSuchPolicyEver": {"TableName": "t"}}]
    elif label == "missing_handler":
        del props["Handler"]
    elif label == "bogus_event_type":
        props["Events"] = {"Ev": {"Type": "NotARealEventType",
                                  "Properties": {"Path": "/x", "Method": "get"}}}
    elif label == "simpletable_no_key_type":
        # SAM reports the SimpleTable's own id, so the table is named Fn to keep the
        # offending-id assertion uniform across legs.
        template["Resources"] = {"Fn": {"Type": "AWS::Serverless::SimpleTable",
                                        "Properties": {"PrimaryKey": {"Name": "pk"}}}}
    elif label == "two_faults":
        props["Policies"] = [{"NoSuchPolicyEver": {"TableName": "t"}}]
        other = json.loads(_base_template(function_name + "-other"))["Resources"]["Fn"]
        del other["Properties"]["Handler"]
        template["Resources"]["Other"] = other
    elif label == "unknown_serverless_type":
        template["Resources"] = {"Fn": {"Type": "AWS::Serverless::NotAThing", "Properties": {}}}
    else:
        raise AssertionError(f"unknown fault label {label!r}")
    return json.dumps(template)


def _stack_named(cfn, stack_name: str, statuses: list[str]) -> bool:
    """Is stack_name among the stacks in any of these statuses? Paginated."""
    for page in cfn.get_paginator("list_stacks").paginate(StackStatusFilter=statuses):
        for summary in page["StackSummaries"]:
            if summary["StackName"] == stack_name:
                return True
    return False


def _template_body(cfn, stack_name: str, stage: str) -> dict:
    """get_template returns a dict for a JSON template and a string for YAML; normalise."""
    body = cfn.get_template(StackName=stack_name, TemplateStage=stage)["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else body


def _error(fn) -> tuple[str, str]:
    """The AWS error (code, message) a call raised. Raises when the call unexpectedly succeeded.

    A falsy sentinel would make an unexpected success read like an error-code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("the call SUCCEEDED; real AWS refuses it, so there is no code to assert")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    """Best-effort log-group teardown; a group Lambda never created is not an error."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s=900.0) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup).

    A REVIEW_IN_PROGRESS shell stack left by a failed change set is deleted the same way.
    """
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(_status, lambda s: s in {"DELETE_COMPLETE", "GONE"}, timeout_s=timeout_s,
                interval_s=5.0, description=f"delete stack {stack_name}")


def _create_change_set(ctx, template_body: str, *, capabilities=None, timeout_s=300.0) -> dict:
    """Create a CREATE change set and poll it to a terminal status.

    The stack teardown is registered before the change set exists, so the REVIEW_IN_PROGRESS
    shell stack a failed transform leaves behind is never leaked.
    """
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    stack_name = _xname(ctx, "stk")
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))
    cfn.create_change_set(
        StackName=stack_name,
        ChangeSetName="sim2real-cs1",
        ChangeSetType="CREATE",
        TemplateBody=template_body,
        Tags=_xsvc_tags_kv(),
        Capabilities=capabilities or ["CAPABILITY_AUTO_EXPAND", "CAPABILITY_IAM"],
    )
    described = _poll_until(
        lambda: cfn.describe_change_set(StackName=stack_name, ChangeSetName="sim2real-cs1"),
        lambda d: d["Status"] in {"CREATE_COMPLETE", "FAILED"},
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"change set for {stack_name}",
    )
    described["stack_name"] = stack_name
    described["change_set_name"] = "sim2real-cs1"
    return described


def _failed_change_set(ctx, template_body: str, label: str) -> tuple[dict, str]:
    """Submit a document expected to fail the transform; return (described, stack_name)."""
    described = _create_change_set(ctx, template_body)
    return described, described["stack_name"]


def _execute_change_set(ctx, stack_name: str, change_set_name: str, *, timeout_s=900.0) -> None:
    """Execute a change set and wait for CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cfn.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s.endswith(("_COMPLETE", "_FAILED")),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {stack_name}",
    )
    assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
