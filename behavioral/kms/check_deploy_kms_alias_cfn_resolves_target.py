"""deploy-kms-alias-cfn-resolves-target."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "deploy-kms-alias-cfn-resolves-target"
GROUP = "state-machine"
SERVICES = ["kms"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  AliasNameParam:
    Type: String
Resources:
  TestKey:
    Type: AWS::KMS::Key
    Properties:
      Description: sim2real behavioral fidelity test key (aliased)
      Enabled: true
      PendingWindowInDays: 7
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: EnableRootAccess
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:${AWS::Partition}:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
  TestAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: !Ref AliasNameParam
      TargetKeyId: !Ref TestKey
Outputs:
  KeyArn:
    Value: !GetAtt TestKey.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::KMS::Alias deployed via CloudFormation resolves to its target key: Encrypt using
    the alias name produces ciphertext that Decrypt confirms was produced by the underlying key
    ARN, and DescribeKey(alias) resolves to that same ARN."""
    alias_name = ctx.unique_name("alias/sim2real-cfn-")
    outputs = _deploy_cfn(ctx, _TEMPLATE, parameters={"AliasNameParam": alias_name})
    key_arn = outputs["KeyArn"]

    kms = ctx.client("kms")
    resolved = kms.describe_key(KeyId=alias_name)["KeyMetadata"]
    assert resolved["Arn"] == key_arn, f"expected DescribeKey({alias_name}) to resolve to {key_arn}, got {resolved['Arn']}"

    plaintext = b"sim2real-cfn-alias-payload"
    ciphertext = kms.encrypt(KeyId=alias_name, Plaintext=plaintext)["CiphertextBlob"]
    # Decrypt with an explicit KeyId validates the ciphertext really was produced under key_arn,
    # not merely under "some key that happens to decrypt the bytes"
    decrypted = kms.decrypt(KeyId=key_arn, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"expected decrypt under {key_arn} to return the original plaintext, got {decrypted!r}"


def _deploy_cfn(ctx, template_body, parameters=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-kms-cfn-alias-")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body}
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    described = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", f"expected stack {stack_name} to reach CREATE_COMPLETE, got {described['StackStatus']}"
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _delete_stack(cfn, stack_name):
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
