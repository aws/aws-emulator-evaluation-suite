"""deploy-inference-profile-cfn-routes-invocation."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import WaiterError

CHECK = "deploy-inference-profile-cfn-routes-invocation"
GROUP = "deploy"
SERVICES = ["bedrock"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: sim2real behavioral fidelity check - application inference profile routes invocation
Parameters:
  ProfileName:
    Type: String
  ModelArn:
    Type: String
Resources:
  Profile:
    Type: AWS::Bedrock::ApplicationInferenceProfile
    Properties:
      InferenceProfileName: !Ref ProfileName
      ModelSource:
        CopyFrom: !Ref ModelArn
Outputs:
  InferenceProfileArn:
    Value: !GetAtt Profile.InferenceProfileArn
"""


def _create_stack_and_await(ctx, template: str, parameters: dict[str, str]) -> tuple[str, list[str]]:
    """Creates the stack and returns (stack_name, failure_reasons); failure_reasons is empty on
    CREATE_COMPLETE. Never raises on a CFN-side failure -- the caller decides what that means."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-bedrock-infprofile-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except WaiterError:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e["ResourceStatus"].endswith("FAILED")
        ]
        return stack_name, reasons
    return stack_name, []


def _pick_system_defined_inference_profile_arn(bedrock) -> str:
    """Prefer a small Amazon model profile; fall back to the first SYSTEM_DEFINED profile."""
    resp = bedrock.list_inference_profiles(typeEquals="SYSTEM_DEFINED", maxResults=1000)
    summaries = resp.get("inferenceProfileSummaries", [])
    assert summaries, "expected at least one SYSTEM_DEFINED inference profile in this region"
    for s in summaries:
        if "amazon.nova-micro" in s["inferenceProfileId"]:
            return s["inferenceProfileArn"]
    return summaries[0]["inferenceProfileArn"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CloudFormation creates an AWS::Bedrock::ApplicationInferenceProfile copied from a
    SYSTEM_DEFINED inference profile, and a Converse call addressed to the stack's
    InferenceProfileArn output returns a non-empty completion.
    """
    bedrock = ctx.client("bedrock")
    runtime = ctx.client("bedrock-runtime")
    cfn = ctx.client("cloudformation")

    source_arn = _pick_system_defined_inference_profile_arn(bedrock)
    profile_name = ctx.unique_name("sim2real-cfn-infprofile-")
    stack_name, reasons = _create_stack_and_await(
        ctx, _TEMPLATE, {"ProfileName": profile_name, "ModelArn": source_arn}
    )
    assert not reasons, f"expected stack {stack_name} to reach CREATE_COMPLETE, got failure reasons {reasons!r}"

    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    profile_arn = next((o["OutputValue"] for o in outputs if o["OutputKey"] == "InferenceProfileArn"), None)
    assert profile_arn, f"expected an InferenceProfileArn output on stack {stack_name}, got {outputs!r}"

    resp = runtime.converse(
        modelId=profile_arn,
        messages=[{"role": "user", "content": [{"text": "Reply with the single word: ok"}]}],
        inferenceConfig={"maxTokens": 16},
    )
    text = "".join(
        block.get("text", "") for block in resp["output"]["message"]["content"]
    ).strip()
    assert text, f"expected a non-empty completion through the CFN-deployed profile {profile_arn}, got {resp!r}"

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
