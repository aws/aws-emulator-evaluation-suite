"""cfn-kms-key-enabled-false-blocks-encrypt-until-enabled-in-place."""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-kms-key-enabled-false-blocks-encrypt-until-enabled-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms"]

_ROOT = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}
_PENDING_DAYS = 7


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN AWS::KMS::Key templated with Enabled false deploys Disabled and refuses
    Encrypt; an Enabled-only update re-enables the same key in place and Encrypt
    round-trips again.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-key.html
    """
    cfn = ctx.client("cloudformation")
    kms = ctx.client("kms")
    stack_name = ctx.unique_name("sim2real-behav-cfnkms-enabled-")

    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=_template(enabled=False))[
        "StackId"
    ]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    _wait_stack(cfn, stack_id, "stack_create_complete")
    key_id = _physical_id(cfn, stack_id, "Key")
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    got = (meta["Enabled"], meta["KeyState"])
    assert got == (False, "Disabled"), f"a templated Enabled=false key: {got!r}, expected (False, 'Disabled')"

    got = _error(lambda: kms.encrypt(KeyId=key_id, Plaintext=b"sim2real-disabled-probe"))
    want = ("DisabledException", f"{key_arn} is disabled.")
    assert got == want, f"Encrypt against the disabled key: {got!r}, expected {want!r}"

    # Effect absent: the refused Encrypt did not change the key's own state.
    still = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    got = (still["Enabled"], still["KeyState"])
    assert got == (False, "Disabled"), f"a refused Encrypt must not change key state: {got!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(enabled=True))
    _wait_stack(cfn, stack_id, "stack_update_complete")
    reenabled_id = _physical_id(cfn, stack_id, "Key")
    assert reenabled_id == key_id, (
        f"an Enabled-only update must keep the same key, got {reenabled_id!r} for {key_id!r}"
    )

    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    got = (meta["Enabled"], meta["KeyState"])
    assert got == (True, "Enabled"), f"after the in-place re-enable: {got!r}, expected (True, 'Enabled')"

    # Positive control: the identical call that was refused now succeeds and round-trips.
    plaintext = b"sim2real-reenabled-probe"
    ciphertext = kms.encrypt(KeyId=key_id, Plaintext=plaintext)["CiphertextBlob"]
    decrypted = kms.decrypt(CiphertextBlob=ciphertext)["Plaintext"]
    assert decrypted == plaintext, f"Decrypt of the re-enabled key's ciphertext: {decrypted!r}"

    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, "stack_delete_complete")
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "PendingDeletion", f"DeleteStack must schedule the key, got KeyState={state!r}"


def _template(*, enabled: bool) -> str:
    return json.dumps(
        {
            "Resources": {
                "Key": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": "sim2real cfn enabled-property test key",
                        "Enabled": enabled,
                        "PendingWindowInDays": _PENDING_DAYS,
                        "KeyPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AccountAdmin",
                                    "Effect": "Allow",
                                    "Principal": {"AWS": _ROOT},
                                    "Action": "kms:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                }
            }
        }
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _wait_stack(cfn, stack_id: str, waiter_name: str) -> None:
    cfn.get_waiter(waiter_name).wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert not status.endswith("ROLLBACK") and not status.endswith("FAILED"), (
        f"{waiter_name} ended {status!r}"
    )


def _delete_stack(cfn, stack_id: str) -> None:
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, "stack_delete_complete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
