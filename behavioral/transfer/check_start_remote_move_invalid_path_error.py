"""start-remote-move-invalid-path-error."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-remote-move-invalid-path-error"
GROUP = "error-semantics"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartRemoteMove on an AS2 connector fails with InvalidRequestException "Remote move not supported for AS2
    connectors" for both a malformed and a well-formed path, while an unknown ConnectorId fails with
    ResourceNotFoundException "Unknown connector"."""
    transfer = ctx.client("transfer")

    role_arn = _create_transfer_role(ctx, "remotemove")

    local_profile_id = transfer.create_profile(As2Id=ctx.unique_name("SIM2REALLOCAL")[:20], ProfileType="LOCAL")[
        "ProfileId"
    ]
    ctx.on_cleanup(lambda: transfer.delete_profile(ProfileId=local_profile_id))
    partner_profile_id = transfer.create_profile(
        As2Id=ctx.unique_name("SIM2REALPARTNER")[:20], ProfileType="PARTNER"
    )["ProfileId"]
    ctx.on_cleanup(lambda: transfer.delete_profile(ProfileId=partner_profile_id))

    connector_id = transfer.create_connector(
        Url="https://sim2real-partner.example.com/as2",
        AccessRole=role_arn,
        As2Config={
            "LocalProfileId": local_profile_id,
            "PartnerProfileId": partner_profile_id,
            "MessageSubject": "sim2real-test",
            "Compression": "DISABLED",
            "EncryptionAlgorithm": "NONE",
            "SigningAlgorithm": "NONE",
            "MdnSigningAlgorithm": "NONE",
            "MdnResponse": "NONE",
        },
    )["ConnectorId"]
    ctx.on_cleanup(lambda: transfer.delete_connector(ConnectorId=connector_id))

    # This connector genuinely exists -- StartRemoteMove against it with a malformed,
    # non-absolute path must be InvalidRequestException, never ResourceNotFoundException.
    code_malformed_path, msg_malformed_path = _err(
        lambda: transfer.start_remote_move(
            ConnectorId=connector_id,
            SourcePath="not-an-absolute-path.txt",
            TargetPath="/sim2real/dest/target.txt",
        )
    )
    assert code_malformed_path == "InvalidRequestException", (
        f"expected InvalidRequestException for a malformed path, got {code_malformed_path!r}"
    )
    assert msg_malformed_path == "Remote move not supported for AS2 connectors", (
        f"unexpected malformed-path message {msg_malformed_path!r}"
    )

    # The identical connector, given a WELL-FORMED absolute path, must get the identical code --
    # proving path validity is not what's being rejected. AS2 connectors don't support remote
    # move at all, so the rejection is unconditional on the connector, not conditional on the path.
    code_wellformed_path, msg_wellformed_path = _err(
        lambda: transfer.start_remote_move(
            ConnectorId=connector_id,
            SourcePath="/sim2real/well-formed/source.txt",
            TargetPath="/sim2real/well-formed/target.txt",
        )
    )
    assert code_wellformed_path == "InvalidRequestException", (
        f"expected InvalidRequestException for a well-formed path on an AS2 connector "
        f"(remote move is unsupported for this connector type regardless of path), got {code_wellformed_path!r}"
    )
    assert msg_wellformed_path == "Remote move not supported for AS2 connectors", (
        f"unexpected well-formed-path message {msg_wellformed_path!r}"
    )

    # A syntactically well-formed but nonexistent ConnectorId must instead be ResourceNotFoundException
    # -- proving the two preconditions (bad request vs. missing resource) are distinct, not conflated.
    bogus_connector_id = "c-00000000000000000"
    code_missing, msg_missing = _err(
        lambda: transfer.start_remote_move(
            ConnectorId=bogus_connector_id,
            SourcePath="/sim2real/source/file.txt",
            TargetPath="/sim2real/dest/file.txt",
        )
    )
    assert code_missing == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent connector, got {code_missing!r}"
    )
    assert msg_missing == "Unknown connector", f"unexpected missing-connector message {msg_missing!r}"
    assert code_malformed_path != code_missing, (
        f"expected the existing-connector code to differ from the missing-connector code, "
        f"both were {code_malformed_path!r}"
    )
    assert code_wellformed_path != code_missing, (
        f"expected the existing-connector code to differ from the missing-connector code, "
        f"both were {code_wellformed_path!r}"
    )


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_transfer_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-transfer-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
