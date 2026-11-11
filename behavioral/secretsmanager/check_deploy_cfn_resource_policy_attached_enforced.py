"""deploy-cfn-resource-policy-attached-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-resource-policy-attached-enforced"
GROUP = "server-side"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN inline ResourcePolicy is attached and denies access identically to the same policy set via PutResourcePolicy."""
    secretsmanager = ctx.client("secretsmanager")
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    caller_arn = identity["Arn"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": {"AWS": root_arn},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }

    # --- secret 1: resource policy attached inline via CloudFormation ---
    stack_name = ctx.unique_name("sim2real-cfn-secpolicy-")
    cfn_secret_name = ctx.unique_name("sim2real-cfnpolicy-secret-")
    template = {
        "Resources": {
            "PolicySecret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {
                    "Name": cfn_secret_name,
                    "SecretString": json.dumps({"value": "cfn-policy-secret"}),
                },
            },
            "PolicySecretPolicy": {
                "Type": "AWS::SecretsManager::ResourcePolicy",
                "Properties": {
                    "SecretId": {"Ref": "PolicySecret"},
                    "BlockPublicPolicy": True,
                    "ResourcePolicy": deny_policy,
                },
            },
        },
        "Outputs": {"SecretArn": {"Value": {"Ref": "PolicySecret"}}},
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _wait_stack_complete(cfn, stack_name, "create")
    cfn_secret_arn = _stack_outputs(cfn, stack_name)["SecretArn"]

    # --- secret 2: an identical deny policy attached directly via PutResourcePolicy ---
    api_secret_name = ctx.unique_name("sim2real-apipolicy-secret-")
    api_secret_arn = secretsmanager.create_secret(
        Name=api_secret_name, SecretString=json.dumps({"value": "api-policy-secret"})
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=api_secret_arn, ForceDeleteWithoutRecovery=True)
    )
    secretsmanager.put_resource_policy(
        SecretId=api_secret_arn, ResourcePolicy=json.dumps(deny_policy), BlockPublicPolicy=True
    )

    # --- secret 3: control, no resource policy at all ---
    control_secret_name = ctx.unique_name("sim2real-controlpolicy-secret-")
    control_secret_arn = secretsmanager.create_secret(
        Name=control_secret_name, SecretString=json.dumps({"value": "control-secret"})
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=control_secret_arn, ForceDeleteWithoutRecovery=True)
    )

    # The CFN-attached policy is present and matches what we asked CloudFormation to attach.
    attached_policy = json.loads(
        secretsmanager.get_resource_policy(SecretId=cfn_secret_arn)["ResourcePolicy"]
    )
    statement = attached_policy["Statement"][0]
    assert statement["Effect"] == "Deny", f"expected Effect Deny, got {statement['Effect']!r}"
    assert statement["Action"] == "secretsmanager:GetSecretValue", (
        f"expected Action secretsmanager:GetSecretValue, got {statement['Action']!r}"
    )
    assert statement["Principal"]["AWS"] == root_arn, (
        f"expected Principal.AWS {root_arn!r}, got {statement['Principal']['AWS']!r}"
    )

    # Enforcement: the CFN-attached policy and the API-attached policy deny GetSecretValue identically.
    for secret_arn in (cfn_secret_arn, api_secret_arn):
        err = _error(lambda: secretsmanager.get_secret_value(SecretId=secret_arn))
        assert err.get("Code") == "AccessDeniedException", (
            f"expected AccessDeniedException for {secret_arn}, got {err!r}"
        )
        expected_message = (
            f"User: {caller_arn} is not authorized to perform: secretsmanager:GetSecretValue "
            f"on resource: {secret_arn} with an explicit deny in a resource-based policy"
        )
        assert err.get("Message") == expected_message, (
            f"expected message {expected_message!r}, got {err.get('Message')!r}"
        )

    # Effect absent: the secret itself is untouched (still exists, describable) despite the denial.
    described = secretsmanager.describe_secret(SecretId=cfn_secret_arn)
    assert described.get("DeletedDate") is None, (
        f"expected DeletedDate absent on a merely-denied secret, got {described.get('DeletedDate')!r}"
    )

    # Positive control: an identical secret without a resource policy is still readable.
    control_value = secretsmanager.get_secret_value(SecretId=control_secret_arn)
    assert json.loads(control_value["SecretString"])["value"] == "control-secret", (
        f"expected control secret value 'control-secret', got {control_value['SecretString']!r}"
    )

    # Restore: removing the deny statement restores GetSecretValue identically regardless of
    # which mechanism originally attached it -- the CFN-templated resource policy and the
    # directly-API-attached one are the same underlying artifact, not two different things that
    # happen to deny the same way.
    secretsmanager.delete_resource_policy(SecretId=cfn_secret_arn)
    restored_cfn = _poll_until_success(lambda: secretsmanager.get_secret_value(SecretId=cfn_secret_arn))
    assert json.loads(restored_cfn["SecretString"])["value"] == "cfn-policy-secret", (
        f"expected CFN-attached secret readable again after policy removal, "
        f"got {restored_cfn['SecretString']!r}"
    )

    secretsmanager.delete_resource_policy(SecretId=api_secret_arn)
    restored_api = _poll_until_success(lambda: secretsmanager.get_secret_value(SecretId=api_secret_arn))
    assert json.loads(restored_api["SecretString"])["value"] == "api-policy-secret", (
        f"expected API-attached secret readable again after policy removal, "
        f"got {restored_api['SecretString']!r}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because turning
    acceptance into a falsy sentinel would let an over-permissive target read as a mere
    code mismatch instead of the stronger "denial never happened" signal it actually is."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _poll_until_success(fn, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"operation never succeeded within {timeout_s}s: {last_err}")


def _wait_stack_complete(cfn, stack_name: str, action: str, timeout_s: float = 180.0) -> None:
    waiter_name = "stack_create_complete" if action == "create" else "stack_delete_complete"
    waiter = cfn.get_waiter(waiter_name)
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(timeout_s // 2))})


def _stack_outputs(cfn, stack_name: str) -> dict:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {}
    for o in stacks[0].get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return outputs


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_complete(cfn, stack_name, "delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
