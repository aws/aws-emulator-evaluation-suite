"""deploy-guardrail-cfn-enforces-blocked-content."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deploy-guardrail-cfn-enforces-blocked-content"
GROUP = "deploy"
SERVICES = ["bedrock"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Description: sim2real behavioral fidelity check - guardrail blocks configured denied content
Parameters:
  GuardrailName:
    Type: String
Resources:
  Guardrail:
    Type: AWS::Bedrock::Guardrail
    Properties:
      Name: !Ref GuardrailName
      BlockedInputMessaging: "This input was blocked by the deployed guardrail."
      BlockedOutputsMessaging: "This output was blocked by the deployed guardrail."
      WordPolicyConfig:
        WordsConfig:
          - Text: "SIM2REALFORBIDDENTERM"
      Tags:
        - Key: sim2real
          Value: guardrail-cfn-blocked-content
Outputs:
  GuardrailId:
    Value: !GetAtt Guardrail.GuardrailId
  GuardrailArn:
    Value: !GetAtt Guardrail.GuardrailArn
"""


def _deploy_cfn(ctx, template: str, parameters: dict[str, str]) -> dict[str, str]:
    from botocore.exceptions import WaiterError

    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-bedrock-guardrail-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
    )

    def _teardown() -> None:
        # The cleanup budget is 60s (separate from the 300s check body budget), so this
        # waiter is capped well under that rather than mirroring the create-side waiter.
        cfn.delete_stack(StackName=stack_name)
        # The waiter succeeds once the stack is gone and raises on DELETE_FAILED or its deadline.
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
        )

    ctx.on_cleanup(_teardown)

    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    except WaiterError as err:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        reasons = [
            f"{e['LogicalResourceId']}[{e['ResourceStatus']}]: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(
            f"stack {stack_name} failed to reach CREATE_COMPLETE: {err}\nfailure reasons: {reasons}"
        ) from err

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    result = {o["OutputKey"]: o["OutputValue"] for o in outputs}
    result["_stack_resources"] = resources
    return result


def _wait_guardrail_ready(ctx, bedrock, guardrail_id, guardrail_arn, guardrail_name, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        # Try both the plain ID and the full ARN in case the CFN-provided identifier
        # form doesn't round-trip through GetGuardrail the same way a console/API-created
        # guardrail's ID would.
        for identifier in (guardrail_id, guardrail_arn):
            try:
                resp = bedrock.get_guardrail(guardrailIdentifier=identifier)
            except ClientError as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    last_error = err
                    continue
                raise
            if resp["status"] == "READY":
                return resp, identifier
            if resp["status"] == "FAILED":
                raise AssertionError(f"guardrail {identifier} failed to become READY: {resp}")
        time.sleep(interval_s)

    # Diagnostic fallback: confirm whether the guardrail exists under a different
    # identifier than the one returned by the stack output, to distinguish an
    # eventual-consistency lag from a genuinely wrong CFN output.
    matches = [
        g for g in bedrock.list_guardrails(maxResults=50).get("guardrails", [])
        if g.get("name") == guardrail_name
    ]
    raise AssertionError(
        f"guardrail id={guardrail_id!r} arn={guardrail_arn!r} (name={guardrail_name!r}) never "
        f"reached READY within {timeout_s}s; last error={last_error!r}; "
        f"list_guardrails() matches by name={matches!r}"
    )


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A guardrail deployed via CloudFormation actually blocks its configured denied content."""

    bedrock = ctx.client("bedrock")
    bedrock_runtime = ctx.client("bedrock-runtime")
    sts = ctx.client("sts")
    caller_account = sts.get_caller_identity()["Account"]

    guardrail_name = ctx.unique_name("sim2real-cfn-guardrail-")
    outputs = _deploy_cfn(ctx, _TEMPLATE, {"GuardrailName": guardrail_name})
    guardrail_id = outputs["GuardrailId"]
    guardrail_arn = outputs["GuardrailArn"]
    assert outputs["_stack_resources"][0]["ResourceStatus"] == "CREATE_COMPLETE", (
        f"expected the Guardrail resource to be CREATE_COMPLETE, got {outputs['_stack_resources']!r}"
    )

    arn_account = guardrail_arn.split(":")[4] if len(guardrail_arn.split(":")) > 4 else None
    if arn_account != caller_account:
        raise AssertionError(
            "the AWS::Bedrock::Guardrail CloudFormation resource handler in this account "
            f"returned a GuardrailArn attributed to account {arn_account!r} instead of the "
            f"caller's own account {caller_account!r} ({guardrail_arn!r}); this is an "
            "environment-specific CFN provisioning issue this check cannot route around"
        )

    from botocore.exceptions import ClientError

    try:
        _, guardrail_id = _wait_guardrail_ready(ctx, bedrock, guardrail_id, guardrail_arn, guardrail_name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "AccessDeniedException" and "different account" in err.response[
            "Error"
        ].get("Message", ""):
            raise AssertionError(
                "GetGuardrail rejected the CFN-provisioned guardrail's own ARN as belonging to a "
                f"'different account' even though its account segment matches the caller "
                f"({caller_account!r}) exactly ({guardrail_arn!r}); the CloudFormation resource "
                "handler for AWS::Bedrock::Guardrail appears to provision this resource in a way "
                "that is not fully usable in this sandbox account, which is an environment "
                "limitation this check cannot route around"
            )
        raise


    blocked_resp = bedrock_runtime.apply_guardrail(

        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": "This message contains SIM2REALFORBIDDENTERM which must be blocked."}}],
    )
    assert blocked_resp["action"] == "GUARDRAIL_INTERVENED", (
        f"expected the deployed guardrail to intervene on its denied word, got action={blocked_resp['action']!r}"
    )

    # Positive control in the same file: clean content is not blocked by the same guardrail.
    clean_resp = bedrock_runtime.apply_guardrail(
        guardrailIdentifier=guardrail_id,
        guardrailVersion="DRAFT",
        source="INPUT",
        content=[{"text": {"text": "This is an entirely unremarkable, harmless sentence."}}],
    )
    assert clean_resp["action"] == "NONE", (
        f"expected clean content to pass through the same guardrail untouched, got action={clean_resp['action']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
