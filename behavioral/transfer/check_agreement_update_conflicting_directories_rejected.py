"""agreement-update-conflicting-directories-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agreement-update-conflicting-directories-rejected"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAgreement with both BaseDirectory and CustomDirectories fails InvalidRequestException
    with its exact message and leaves the agreement unchanged; CustomDirectories alone succeeds.

    Reference: https://docs.aws.amazon.com/transfer/latest/APIReference/API_UpdateAgreement.html"""
    transfer = ctx.client("transfer")

    vpc_id, subnet_id = _default_vpc_subnet(ctx)

    as2_server_id = transfer.create_server(
        Protocols=["AS2"],
        ProtocolDetails={"As2Transports": ["HTTP"]},
        EndpointType="VPC",
        EndpointDetails={"VpcId": vpc_id, "SubnetIds": [subnet_id]},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=as2_server_id))

    role_arn = _create_transfer_role(ctx, "agreement-neg")

    local_profile_id = transfer.create_profile(
        As2Id=ctx.unique_name("LOCALAS2-").replace("-", "").upper(),
        ProfileType="LOCAL",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ProfileId"]
    ctx.on_cleanup(lambda: transfer.delete_profile(ProfileId=local_profile_id))

    partner_profile_id = transfer.create_profile(
        As2Id=ctx.unique_name("PARTNERAS2-").replace("-", "").upper(),
        ProfileType="PARTNER",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ProfileId"]
    ctx.on_cleanup(lambda: transfer.delete_profile(ProfileId=partner_profile_id))

    bucket = ctx.unique_name("sim2real-bucket")
    base_dir = f"/{bucket}/as2"

    agreement_id = transfer.create_agreement(
        ServerId=as2_server_id,
        LocalProfileId=local_profile_id,
        PartnerProfileId=partner_profile_id,
        AccessRole=role_arn,
        BaseDirectory=base_dir,
        Status="INACTIVE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AgreementId"]
    ctx.on_cleanup(
        lambda: transfer.delete_agreement(AgreementId=agreement_id, ServerId=as2_server_id)
    )

    custom_dirs = {
        "FailedFilesDirectory": f"/{bucket}/failed",
        "MdnFilesDirectory": f"/{bucket}/mdn",
        "PayloadFilesDirectory": f"/{bucket}/payload",
        "StatusFilesDirectory": f"/{bucket}/status",
        "TemporaryFilesDirectory": f"/{bucket}/temp",
    }

    # negative: specifying BOTH BaseDirectory and CustomDirectories must fail
    error = _client_error(
        lambda: transfer.update_agreement(
            AgreementId=agreement_id,
            ServerId=as2_server_id,
            BaseDirectory=base_dir,
            CustomDirectories=custom_dirs,
        )
    )
    expected_message = (
        f"Both BaseDirectory and CustomDirectories are configured. BaseDirectory: {base_dir}, "
        "CustomDirectories: CustomDirectoriesType("
        f"failedFilesDirectory={custom_dirs['FailedFilesDirectory']}, "
        f"mdnFilesDirectory={custom_dirs['MdnFilesDirectory']}, "
        f"payloadFilesDirectory={custom_dirs['PayloadFilesDirectory']}, "
        f"statusFilesDirectory={custom_dirs['StatusFilesDirectory']}, "
        f"temporaryFilesDirectory={custom_dirs['TemporaryFilesDirectory']})"
    )
    assert error == ("InvalidRequestException", expected_message), error

    # effect absent: still using the original BaseDirectory, no CustomDirectories set
    unchanged = transfer.describe_agreement(AgreementId=agreement_id, ServerId=as2_server_id)[
        "Agreement"
    ]
    assert unchanged.get("BaseDirectory") == base_dir, (
        f"expected BaseDirectory {base_dir!r} unchanged, got {unchanged.get('BaseDirectory')!r}"
    )
    assert "CustomDirectories" not in unchanged, (
        f"expected no CustomDirectories after rejected update, got {unchanged.get('CustomDirectories')!r}"
    )

    # positive control: the identical update with ONLY CustomDirectories succeeds
    transfer.update_agreement(
        AgreementId=agreement_id, ServerId=as2_server_id, CustomDirectories=custom_dirs
    )
    updated = transfer.describe_agreement(AgreementId=agreement_id, ServerId=as2_server_id)[
        "Agreement"
    ]
    assert updated.get("CustomDirectories") == custom_dirs, (
        f"expected CustomDirectories {custom_dirs!r}, got {updated.get('CustomDirectories')!r}"
    )


def _default_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError(f"no subnets found in vpc {vpc_id}")
    return vpc_id, subnets[0]["SubnetId"]


def _client_error(fn):
    """The (code, message) of a refused call; raises when the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_transfer_role(ctx, suffix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-transfer-{suffix}-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "transfer.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="inline",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
    _wait_for_role(ctx, role_name)
    return role_arn


def _wait_for_role(ctx, role_name, timeout_s=30.0, interval_s=2.0):
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            return
        except ClientError:
            time.sleep(interval_s)
    raise AssertionError(f"IAM role {role_name} never became visible within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

