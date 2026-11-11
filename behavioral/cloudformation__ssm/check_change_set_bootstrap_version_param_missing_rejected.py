"""change-set-bootstrap-version-param-missing-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-bootstrap-version-param-missing-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

_ASSERT_DESCRIPTION = (
    "CDK bootstrap stack version 6 required. Please run 'cdk bootstrap' with a recent version of "
    "the CDK CLI."
)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CDK template whose BootstrapVersion SSM parameter does not exist is refused at
    CreateChangeSet with a ValidationError and leaves no stack; once the parameter exists the same
    call succeeds and the change set carries the resolved value.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack = ctx.unique_name("sim2real-cfn-boot-")
    qualifier = ctx.unique_name("s2r")[:10]
    version_param = f"/cdk-bootstrap/{qualifier}/version"
    body = _template(version_param)

    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    refused = _err(lambda: cfn.create_change_set(
        StackName=stack, ChangeSetName="deploy", ChangeSetType="CREATE", TemplateBody=body,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}]))
    assert refused == (
        "ValidationError",
        f"Unable to fetch parameters [{version_param}] from parameter store for this account.",
    ), f"CreateChangeSet with a missing bootstrap version parameter gave {refused!r}"
    absent = _err(lambda: cfn.describe_stacks(StackName=stack))
    assert absent == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"the refused change set left a stack behind: {absent!r}"
    )

    ssm.put_parameter(
        Name=version_param, Value="21", Type="String",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: ssm.delete_parameter(Name=version_param), "ParameterNotFound"))
    stack_id = cfn.create_change_set(
        StackName=stack, ChangeSetName="deploy", ChangeSetType="CREATE", TemplateBody=body,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}])["StackId"]
    described = _wait_change_set(cfn, stack_id, "deploy")
    params = {p["ParameterKey"]: p for p in described["Parameters"]}
    got = (params["BootstrapVersion"]["ParameterValue"], params["BootstrapVersion"].get("ResolvedValue"))
    assert got == (version_param, "21"), (
        f"the change set's BootstrapVersion parameter is {params['BootstrapVersion']!r}"
    )
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "REVIEW_IN_PROGRESS", f"the unexecuted change set's stack is {status!r}"


def _template(version_param: str) -> str:
    """The parameter and rule every CDK-synthesized stack carries, around one free resource."""
    return json.dumps({
        "Parameters": {"BootstrapVersion": {
            "Type": "AWS::SSM::Parameter::Value<String>",
            "Default": version_param,
            "Description": "Version of the CDK Bootstrap resources in this environment, "
                           "automatically retrieved from SSM Parameter Store. [cdk:skip]",
        }},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
        "Rules": {"CheckBootstrapVersion": {"Assertions": [{
            "Assert": {"Fn::Not": [{"Fn::Contains": [["1", "2", "3", "4", "5"],
                                                     {"Ref": "BootstrapVersion"}]}]},
            "AssertDescription": _ASSERT_DESCRIPTION,
        }]}},
    })


def _wait_change_set(cfn, stack_id: str, name: str, *, timeout_s: float = 120.0) -> dict:
    """DescribeChangeSet once it is CREATE_COMPLETE; raises on FAILED or timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        described = cfn.describe_change_set(StackName=stack_id, ChangeSetName=name)
        if described["Status"] == "CREATE_COMPLETE":
            return described
        if described["Status"] == "FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"change set {name!r} is {described['Status']!r}: {described.get('StatusReason')!r}"
            )
        time.sleep(2.0)


def _err(fn) -> tuple[str, str]:
    """The (code, message) a call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

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
