"""cfn-kms-signing-key-public-key-and-verify-round-trip."""

from __future__ import annotations

import json

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from behavioral_harness import tags

CHECK = "cfn-kms-signing-key-public-key-and-verify-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms"]

_ROOT = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}
_PENDING_DAYS = 7
_SIGNING_ALGORITHM = "ECDSA_SHA_256"
_MESSAGE = b"sim2real-cfn-signing-key-payload"


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN AWS::KMS::Key templated with KeySpec ECC_NIST_P256 and KeyUsage SIGN_VERIFY
    publishes a matching ECDSA public key, signs and self-verifies, and stops signing once
    its stack is deleted.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kms-key.html
    """
    cfn = ctx.client("cloudformation")
    kms = ctx.client("kms")
    stack_name = ctx.unique_name("sim2real-behav-cfnkms-sign-")

    stack_id = cfn.create_stack(StackName=stack_name, TemplateBody=_template())["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    _wait_stack(cfn, stack_id, "stack_create_complete")
    key_id = _physical_id(cfn, stack_id, "SigningKey")
    key_arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]

    want_spec_usage_algs = ("ECC_NIST_P256", "SIGN_VERIFY", {_SIGNING_ALGORITHM})

    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    got = (meta["KeySpec"], meta["KeyUsage"], set(meta["SigningAlgorithms"]))
    assert got == want_spec_usage_algs, (
        f"DescribeKey of the templated key: {got!r}, expected {want_spec_usage_algs!r}"
    )
    assert meta["KeyState"] == "Enabled", f"a newly deployed key must be Enabled: {meta!r}"
    assert "EncryptionAlgorithms" not in meta, (
        f"a SIGN_VERIFY key must not advertise EncryptionAlgorithms: {meta!r}"
    )

    pub = kms.get_public_key(KeyId=key_id)
    got = (pub["KeySpec"], pub["KeyUsage"], set(pub["SigningAlgorithms"]))
    assert got == want_spec_usage_algs, (
        f"GetPublicKey of the templated key: {got!r}, expected {want_spec_usage_algs!r}"
    )
    public_key = load_der_public_key(pub["PublicKey"])
    assert isinstance(public_key, ec.EllipticCurvePublicKey), (
        f"GetPublicKey's DER key must decode to an EC public key, got {type(public_key).__name__}"
    )
    assert public_key.curve.name == "secp256r1", (
        f"ECC_NIST_P256 must publish a secp256r1 point, got {public_key.curve.name!r}"
    )

    signed = kms.sign(
        KeyId=key_id, Message=_MESSAGE, MessageType="RAW", SigningAlgorithm=_SIGNING_ALGORITHM
    )
    assert signed["KeyId"] == key_arn, f"Sign must name the key {key_arn!r}: {signed!r}"

    verdict = kms.verify(
        KeyId=key_id,
        Message=_MESSAGE,
        Signature=signed["Signature"],
        SigningAlgorithm=_SIGNING_ALGORITHM,
    )
    got = (verdict["SignatureValid"], verdict["SigningAlgorithm"], verdict["KeyId"])
    want = (True, _SIGNING_ALGORITHM, key_arn)
    assert got == want, f"Verify of KMS's own signature: {got!r}, expected {want!r}"

    cfn.delete_stack(StackName=stack_id)
    _wait_stack(cfn, stack_id, "stack_delete_complete")
    state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert state == "PendingDeletion", f"DeleteStack must schedule the key, got KeyState={state!r}"

    want = ("KMSInvalidStateException", f"{key_arn} is pending deletion.")
    got = _poll_until_refused(
        lambda: kms.sign(
            KeyId=key_id, Message=_MESSAGE, MessageType="RAW", SigningAlgorithm=_SIGNING_ALGORITHM
        ),
        want,
    )
    assert got == want, f"Sign on a pending-deletion key: {got!r}, expected {want!r}"


def _template() -> str:
    return json.dumps(
        {
            "Resources": {
                "SigningKey": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": "sim2real cfn signing key",
                        "KeySpec": "ECC_NIST_P256",
                        "KeyUsage": "SIGN_VERIFY",
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


def _poll_until_refused(fn, want: tuple[str, str], *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Call fn() until it raises the exact (code, message) want; a success is retried.

    Pending-deletion reaches the crypto backend slightly after DescribeKey shows it, so a
    call that still succeeds is retried rather than failing on the first attempt.
    """
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message") or ""
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"still succeeded after {timeout_s:.0f}s waiting for {want!r}: {result!r}"
            )
        time.sleep(interval_s)


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
