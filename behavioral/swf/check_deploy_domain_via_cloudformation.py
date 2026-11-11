"""deploy-domain-via-cloudformation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-domain-via-cloudformation"
GROUP = "deploy"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateStack rejects a template declaring AWS::SWF::Domain with ValidationError
    "Unrecognized resource types", since CloudFormation has no SWF resource type, while the
    plain SWF API path (RegisterDomain, RegisterWorkflowType, StartWorkflowExecution) works."""
    cfn = ctx.client("cloudformation")
    swf = ctx.client("swf")

    stack_name = ctx.unique_name("sim2real-swf-cfn-")
    domain_name = ctx.unique_name("sim2real-swf-domain-")
    template_body = json.dumps(
        {
            "Parameters": {"DomainName": {"Type": "String"}},
            "Resources": {
                "SwfDomain": {
                    "Type": "AWS::SWF::Domain",
                    "Properties": {
                        "Name": {"Ref": "DomainName"},
                        "WorkflowExecutionRetentionPeriodInDays": "1",
                    },
                }
            },
            "Outputs": {"DomainName": {"Value": {"Ref": "SwfDomain"}}},
        }
    )

    # 1) Overly-permissive check: AWS::SWF::Domain is not a real CFN resource type.
    #    Real AWS rejects the stack outright with a ValidationError -- it never even
    #    reaches CREATE_IN_PROGRESS.
    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[{"ParameterKey": "DomainName", "ParameterValue": domain_name}],
        )
    except Exception as exc:  # botocore.exceptions.ClientError
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        message = getattr(exc, "response", {}).get("Error", {}).get("Message", "")
        assert code == "ValidationError", f"expected ValidationError, got {code}: {message}"
        assert message == "Template format error: Unrecognized resource types: [AWS::SWF::Domain]", message
    else:
        # If somehow accepted, make sure it doesn't fake its way to success.
        ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
        raise AssertionError(
            "CreateStack with AWS::SWF::Domain was accepted; real AWS rejects this "
            "resource type at validation time"
        )

    # 2) The only real way to "deploy" an SWF domain is the plain SWF API. Confirm
    #    that path actually works end-to-end: RegisterDomain -> DescribeDomain ->
    #    RegisterWorkflowType -> StartWorkflowExecution.
    swf.register_domain(
        name=domain_name,
        workflowExecutionRetentionPeriodInDays="1",
    )
    # SWF has no DeleteDomain: a deprecated domain stays in the account and counts toward its registered-domain quota.
    ctx.on_cleanup(lambda: swf.deprecate_domain(name=domain_name))

    described = _wait_for_domain_registered(ctx, domain_name)
    assert described["domainInfo"]["status"] == "REGISTERED"
    assert described["domainInfo"]["name"] == domain_name

    task_list = {"name": ctx.unique_name("sim2real-swf-tasklist-")}
    wf_type_name = ctx.unique_name("sim2real-swf-wftype-")
    swf.register_workflow_type(
        domain=domain_name,
        name=wf_type_name,
        version="1.0",
        defaultTaskStartToCloseTimeout="30",
        defaultExecutionStartToCloseTimeout="60",
        defaultTaskList=task_list,
        defaultChildPolicy="TERMINATE",
    )

    workflow_id = ctx.unique_name("sim2real-swf-wf-")
    start_resp = swf.start_workflow_execution(
        domain=domain_name,
        workflowId=workflow_id,
        workflowType={"name": wf_type_name, "version": "1.0"},
        taskList=task_list,
    )
    run_id = start_resp["runId"]
    assert run_id
    ctx.on_cleanup(
        lambda: swf.terminate_workflow_execution(
            domain=domain_name, workflowId=workflow_id, runId=run_id
        )
    )

    described_exec = swf.describe_workflow_execution(
        domain=domain_name, execution={"workflowId": workflow_id, "runId": run_id}
    )
    assert described_exec["executionInfo"]["executionStatus"] == "OPEN"
    assert described_exec["executionInfo"]["workflowType"]["name"] == wf_type_name


def _wait_for_domain_registered(ctx, domain_name, timeout_s=60.0, interval_s=2.0):
    swf = ctx.client("swf")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            described = swf.describe_domain(name=domain_name)
        except Exception as exc:
            last = exc
            time.sleep(interval_s)
            continue
        if described["domainInfo"]["status"] == "REGISTERED":
            return described
        last = described
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} never reached REGISTERED: {last}")


# ===== stack helpers =====
def _wait_for_stack_status(ctx, stack_name, target_status, timeout_s=180.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if status == target_status:
            return
        if status.endswith("FAILED") or status.endswith("ROLLBACK_COMPLETE"):
            raise AssertionError(f"stack {stack_name} entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_status} within {timeout_s}s")


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    # A single-domain stack deletes well inside the 60 s cleanup budget.
    deadline = time.monotonic() + 50.0
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} was not deleted within 50s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
