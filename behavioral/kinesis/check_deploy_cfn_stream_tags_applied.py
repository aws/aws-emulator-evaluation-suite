"""deploy-cfn-stream-tags-applied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stream-tags-applied"
GROUP = "server-side"
SERVICES = ["kinesis"]

_TEMPLATE = """\
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Sim2RealStream:
    Type: AWS::Kinesis::Stream
    Properties:
      ShardCount: 1
      Tags:
        - Key: sim2real-behav-check
          Value: cfn-tags-applied
Outputs:
  StreamName:
    Value: !Ref Sim2RealStream
  StreamArn:
    Value: !GetAtt Sim2RealStream.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags declared on a CloudFormation AWS::Kinesis::Stream are returned by ListTagsForResource.
    After stack deletion the same call fails with ResourceNotFoundException and its message."""
    cfn, stack_name, outputs = _deploy_cfn(ctx, _TEMPLATE)
    stream_arn = outputs["StreamArn"]

    kinesis = ctx.client("kinesis")
    tags = kinesis.list_tags_for_resource(ResourceARN=stream_arn)["Tags"]
    by_key = {t["Key"]: t["Value"] for t in tags}
    assert by_key.get("sim2real-behav-check") == "cfn-tags-applied", (
        f"expected the CFN-declared tag to be present, got tags={by_key!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    gone_code, gone_message = _error(lambda: kinesis.list_tags_for_resource(ResourceARN=stream_arn))
    assert gone_code == "ResourceNotFoundException", (
        "expected ListTagsForResource on the stack-deleted stream to be "
        f"ResourceNotFoundException, got {gone_code!r}"
    )
    expected_message = f"Stream {outputs['StreamName']} under account {ctx.account} not found."
    assert gone_message == expected_message, f"expected message {expected_message!r}, got {gone_message!r}"


def _deploy_cfn(ctx, template_body):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-kinesis-cfntags-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("Outputs", [])
    return cfn, stack_name, {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
