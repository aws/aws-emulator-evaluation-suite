"""put-resource-policy-public-principal-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-resource-policy-public-principal-rejected"
GROUP = "overly-permissive"
SERVICES = ["payment-cryptography"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with a "*" principal gets PublicPolicyException with its exact message and no
    policy is attached, while the same policy scoped to one external account is accepted and
    GetResourcePolicy returns it verbatim."""
    pc = ctx.client("payment-cryptography")
    key_attributes = {
        "KeyUsage": "TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY",
        "KeyClass": "SYMMETRIC_KEY",
        "KeyAlgorithm": "AES_128",
        "KeyModesOfUse": {"Encrypt": True, "Decrypt": True, "Wrap": True, "Unwrap": True},
    }
    created = pc.create_key(
        KeyAttributes=key_attributes, Exportable=True, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["Key"]
    arn = created["KeyArn"]
    ctx.on_cleanup(lambda: _safe_delete(pc, arn))

    public_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["payment-cryptography:GetPublicKeyCertificate"],
                    "Resource": "*",
                }
            ],
        }
    )
    error = _must_reject(lambda: pc.put_resource_policy(ResourceArn=arn, Policy=public_policy))
    assert error.get("Code") == "PublicPolicyException", (
        f"expected PublicPolicyException for a policy granting the wildcard principal, got {error!r}"
    )
    expected_message = "The resource policy must not grant public access to the resource."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # a key with no policy attached reads back the empty policy document
    still_no_policy = pc.get_resource_policy(ResourceArn=arn)
    assert still_no_policy["Policy"] == "{}", (
        f"expected no policy attached after the rejected public policy, got {still_no_policy['Policy']!r}"
    )

    # positive control: a scoped, non-public policy is accepted
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "payment-cryptography:GetPublicKeyCertificate",
                "Resource": "*",
            }
        ],
    }
    pc.put_resource_policy(ResourceArn=arn, Policy=json.dumps(scoped_policy))
    ctx.on_cleanup(lambda: _safe_delete_policy(pc, arn))
    fetched = pc.get_resource_policy(ResourceArn=arn)
    fetched_policy = json.loads(fetched["Policy"])
    assert fetched_policy == scoped_policy, (
        f"positive-control policy mismatch: wrote {scoped_policy!r}, read back {fetched_policy!r}"
    )


def _must_reject(fn):
    """Call fn(); return its ClientError Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a policy real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"expected PutResourcePolicy to reject the wildcard-principal policy, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _safe_delete(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_key(KeyIdentifier=arn, DeleteKeyInDays=3)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_policy(pc, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        pc.delete_resource_policy(ResourceArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
