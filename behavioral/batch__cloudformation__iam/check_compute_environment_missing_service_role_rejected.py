"""compute-environment-missing-service-role-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "compute-environment-missing-service-role-rejected"
GROUP = "deploy"
SERVICES = ["batch", "cloudformation", "iam"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}
_SERVICE_POLICY = "arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole"


def _role_resource() -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "batch.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            },
            "ManagedPolicyArns": [_SERVICE_POLICY],
        },
    }


def _template(ce_name: str, *, with_role: bool) -> str:
    ce_props = {"Type": "UNMANAGED", "ComputeEnvironmentName": ce_name}
    resources = {"CE": {"Type": "AWS::Batch::ComputeEnvironment", "Properties": ce_props}}
    if with_role:
        resources["Role"] = _role_resource()
        ce_props["ServiceRole"] = {"Fn::GetAtt": ["Role", "Arn"]}
    return json.dumps({"Resources": resources})


def _wait_terminal(cf, stack_id: str, *, timeout_s: float = 240.0, interval_s: float = 2.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id!r} terminal not met within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cf, stack_id: str, *, timeout_s: float = 300.0) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id, timeout_s=timeout_s)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended in {status!r}, expected DELETE_COMPLETE")


def _resource_status_reason(cf, stack_id: str, logical_id: str) -> str:
    pages = cf.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    for page in pages:
        for event in page["StackEvents"]:
            if event["LogicalResourceId"] == logical_id and event["ResourceStatus"] == "CREATE_FAILED":
                return event["ResourceStatusReason"]
    raise AssertionError(f"no CREATE_FAILED event found for {logical_id!r} in stack {stack_id!r}")


def _attached_policies(iam, role_name: str) -> list[str]:
    pages = iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name)
    return sorted(p["PolicyArn"] for page in pages for p in page["AttachedPolicies"])


@tags(
    "axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """AWS::Batch::ComputeEnvironment without ServiceRole is refused with Batch's exact reason, the
    stack rolls back and Batch holds no such environment, while the same template plus a
    ServiceRole deploys and reads back from Batch and IAM.
    """
    cf = ctx.client("cloudformation")
    batch = ctx.client("batch")
    iam = ctx.client("iam")
    stack_tags = [{"Key": "sim2real", "Value": CHECK}]

    ok_name = ctx.unique_name("sim2real-behav-cerole-ok-")
    ok_ce_name = ctx.unique_name("sim2real-behav-cerole-okce-")
    ok_stack_id = cf.create_stack(
        StackName=ok_name, TemplateBody=_template(ok_ce_name, with_role=True),
        Capabilities=["CAPABILITY_IAM"], Tags=stack_tags,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, ok_stack_id))
    status = _wait_terminal(cf, ok_stack_id)
    assert status == "CREATE_COMPLETE", (
        f"positive control: stack {ok_name!r} with a ServiceRole ended in {status!r}, expected "
        f"CREATE_COMPLETE"
    )
    role_name = cf.describe_stack_resource(StackName=ok_stack_id, LogicalResourceId="Role")[
        "StackResourceDetail"]["PhysicalResourceId"]
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    assert _attached_policies(iam, role_name) == [_SERVICE_POLICY], (
        f"positive control: role attached policies read back as {_attached_policies(iam, role_name)!r}"
    )
    ok_ce = batch.describe_compute_environments(computeEnvironments=[ok_ce_name])["computeEnvironments"]
    got = [(ce["computeEnvironmentName"], ce["type"], ce.get("serviceRole")) for ce in ok_ce]
    assert got == [(ok_ce_name, "UNMANAGED", role_arn)], (
        f"positive control: Batch reads back {got!r}, expected [({ok_ce_name!r}, 'UNMANAGED', "
        f"the stack role's ARN)]"
    )

    bad_name = ctx.unique_name("sim2real-behav-cerole-bad-")
    bad_ce_name = ctx.unique_name("sim2real-behav-cerole-badce-")
    bad_stack_id = cf.create_stack(
        StackName=bad_name, TemplateBody=_template(bad_ce_name, with_role=False), Tags=stack_tags,
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cf, bad_stack_id))
    status = _wait_terminal(cf, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_name!r} without a ServiceRole ended in {status!r}, expected ROLLBACK_COMPLETE"
    )
    reason = _resource_status_reason(cf, bad_stack_id, "CE")
    expected = (
        'Resource handler returned message: "Error executing request, Exception : ServiceRole is '
        'required., RequestId: {request_id} (Service: Batch, Status Code: 400, Request ID: '
        '{request_id}) (SDK Attempt Count: 1)" (RequestToken: {request_token}, HandlerErrorCode: '
        'InvalidRequest)'
    )
    assert _mask_ids(reason) == expected, _mask_ids(reason)

    bad_ce = batch.describe_compute_environments(computeEnvironments=[bad_ce_name])["computeEnvironments"]
    assert bad_ce == [], (
        f"the rejected create left compute environment {bad_ce_name!r} in Batch: {bad_ce!r}"
    )


def _mask_ids(reason: str) -> str:
    """Replace the Batch request ids and CloudFormation RequestToken with placeholders."""
    reason = re.sub(r"RequestId: [0-9a-f-]+", "RequestId: {request_id}", reason)
    reason = re.sub(r"Request ID: [0-9a-f-]+", "Request ID: {request_id}", reason)
    reason = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: {request_token}", reason)
    return reason


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
