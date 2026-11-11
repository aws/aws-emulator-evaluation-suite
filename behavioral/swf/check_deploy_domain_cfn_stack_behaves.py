"""deploy-domain-cfn-stack-behaves."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-domain-cfn-stack-behaves"
GROUP = "deploy"
SERVICES = ["swf"]


@tags("axis:rejection", "cap:c1", "plane:control")
def run(ctx) -> None:
    """CloudFormation has no AWS::SWF::Domain resource type: CreateStack rejects the template with
    ValidationError "Unrecognized resource types", while ValidateTemplate on a supported type
    succeeds (positive control) and SWF never sees the domain."""
    cfn = ctx.client("cloudformation")
    swf = ctx.client("swf")

    domain_name = ctx.unique_name("sim2real-swf-cfndom-")
    stack_name = ctx.unique_name("sim2real-swf-stack-")

    # Positive control: CloudFormation's template-validation pipeline works for
    # this account/region against a resource type it genuinely supports, so the
    # rejection asserted below cannot be a broken-credentials/permissions false
    # positive. No stack is created by ValidateTemplate.
    cfn.validate_template(
        TemplateBody=json.dumps(
            {"Resources": {"ControlTopic": {"Type": "AWS::SNS::Topic", "Properties": {}}}}
        )
    )

    template = {
        "Resources": {
            "SWFDomain": {
                "Type": "AWS::SWF::Domain",
                "Properties": {
                    "Name": domain_name,
                    "WorkflowExecutionRetentionPeriodInDays": "1",
                },
            }
        },
        "Outputs": {"DomainName": {"Value": {"Ref": "SWFDomain"}}},
    }

    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Tags=[{"Key": "sim2real", "Value": "deploy-domain-cfn-stack-behaves"}],
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        assert code == "ValidationError", (
            f"expected CloudFormation to reject AWS::SWF::Domain with ValidationError, "
            f"got {code}: {message}"
        )
        assert message == "Template format error: Unrecognized resource types: [AWS::SWF::Domain]", (
            f"expected the rejection to name AWS::SWF::Domain, got: {message}"
        )
    else:
        # If CreateStack unexpectedly succeeded (e.g. CloudFormation added SWF
        # support), fail loudly rather than silently accept — that would be real
        # news worth rewriting this check to actually exercise.
        ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
        raise AssertionError(
            "CreateStack with AWS::SWF::Domain unexpectedly succeeded — CloudFormation "
            "may now support SWF; this check should be rewritten to exercise the real "
            "deploy path instead of asserting the rejection."
        )

    # Effect-absent at the destination: CreateStack was rejected at template-
    # validation time, before any provisioning began, so SWF must never have seen
    # this domain — there is no CFN-provisioned path to it, on any target.
    try:
        swf.describe_domain(name=domain_name)
    except ClientError as describe_exc:
        describe_code = describe_exc.response.get("Error", {}).get("Code", "")
        assert describe_code == "UnknownResourceFault", (
            f"expected DescribeDomain for a never-created domain to raise "
            f"UnknownResourceFault, got {describe_code}: {describe_exc}"
        )
        describe_message = describe_exc.response.get("Error", {}).get("Message")
        assert describe_message == f"Unknown domain: {domain_name}", describe_message
    else:
        raise AssertionError(
            f"domain {domain_name} exists in SWF even though CreateStack was "
            f"rejected at validation time — the rejected CFN deploy had a side "
            f"effect after all"
        )


# A single-domain stack deletes well inside the 60 s cleanup budget.
def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
