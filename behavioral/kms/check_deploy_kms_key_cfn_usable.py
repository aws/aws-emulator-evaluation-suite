"""deploy-kms-key-cfn-usable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-kms-key-cfn-usable"
GROUP = "state-machine"
SERVICES = ["kms"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  TestKey:
    Type: AWS::KMS::Key
    Properties:
      Description: sim2real behavioral fidelity test key
      Enabled: true
      # 7 is the minimum AWS allows (ScheduleKeyDeletion floor) -- stack deletion cannot make the
      # key gone-gone, so this only bounds how long the unavoidable PendingDeletion tail is.
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
      Tags:
        - Key: sim2real:managed
          Value: 'true'
Outputs:
  KeyArn:
    Value: !GetAtt TestKey.Arn
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::KMS::Key deployed via CloudFormation is Enabled and round-trips Encrypt/Decrypt;
    after stack deletion the key is PendingDeletion and Encrypt fails KMSInvalidStateException."""
    stack_name, outputs = _deploy_cfn(ctx, _TEMPLATE)
    key_arn = outputs["KeyArn"]

    kms = ctx.client("kms")
    meta = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert meta["KeyState"] == "Enabled"
    assert meta["Enabled"] is True

    plaintext = b"sim2real-cfn-key-payload"
    ciphertext = kms.encrypt(KeyId=key_arn, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(KeyId=key_arn, CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext

    _delete_stack(ctx.client("cloudformation"), stack_name)
    post = kms.describe_key(KeyId=key_arn)["KeyMetadata"]
    assert post["KeyState"] == "PendingDeletion", (
        f"expected PendingDeletion after stack delete, got {post['KeyState']}"
    )
    # The crypto-operation block can lag the PendingDeletion KeyState, so retry within a bound.
    deadline = time.monotonic() + 60
    err = {}
    while time.monotonic() < deadline:
        try:
            kms.encrypt(KeyId=key_arn, Plaintext=plaintext)
        except ClientError as e:
            err = e.response["Error"]
            break
        time.sleep(3)
    assert err.get("Code") == "KMSInvalidStateException", (
        f"encrypt against a PendingDeletion key never rejected within 60s (last error: {err})"
    )
    assert err.get("Message") == f"{key_arn} is pending deletion.", (
        f"expected message {key_arn + ' is pending deletion.'!r}, got {err.get('Message')!r}"
    )


def _deploy_cfn(ctx, template_body, parameters=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-kms-cfn-")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body}
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    described = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE"
    return stack_name, {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _delete_stack(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ValidationError":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
