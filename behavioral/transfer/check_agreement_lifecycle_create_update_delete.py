"""agreement-lifecycle-create-update-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "agreement-lifecycle-create-update-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An agreement created INACTIVE on an AS2-configured server transitions to ACTIVE
    via UpdateAgreement, and DescribeAgreement/ListAgreements stop returning it after
    DeleteAgreement."""
    transfer = ctx.client("transfer")
    tag_set = [{"Key": "sim2real-check", "Value": CHECK}]

    vpc_id, subnet_id = _vpc_subnet(ctx)
    server_id = transfer.create_server(
        Protocols=["AS2"],
        ProtocolDetails={"As2Transports": ["HTTP"]},
        EndpointType="VPC",
        EndpointDetails={"VpcId": vpc_id, "SubnetIds": [subnet_id]},
        Tags=tag_set,
    )["ServerId"]
    ctx.on_cleanup(lambda: transfer.delete_server(ServerId=server_id))

    role_arn = _create_transfer_role(ctx, "agreement")

    local_profile_id = transfer.create_profile(
        As2Id=ctx.unique_name("LOCALAS2-").replace("-", "").upper(), ProfileType="LOCAL", Tags=tag_set
    )["ProfileId"]
    ctx.on_cleanup(lambda: transfer.delete_profile(ProfileId=local_profile_id))

    partner_profile_id = transfer.create_profile(
        As2Id=ctx.unique_name("PARTNERAS2-").replace("-", "").upper(), ProfileType="PARTNER", Tags=tag_set
    )["ProfileId"]
    ctx.on_cleanup(lambda: transfer.delete_profile(ProfileId=partner_profile_id))

    base_dir = f"/{ctx.unique_name('sim2real-bucket')}/as2"
    agreement_id = _retry_role_propagation(
        lambda: transfer.create_agreement(
            ServerId=server_id,
            LocalProfileId=local_profile_id,
            PartnerProfileId=partner_profile_id,
            AccessRole=role_arn,
            BaseDirectory=base_dir,
            Status="INACTIVE",
            Tags=tag_set,
        )
    )["AgreementId"]
    deleted = {"v": False}

    def _cleanup_agreement():
        if not deleted["v"]:
            transfer.delete_agreement(AgreementId=agreement_id, ServerId=server_id)

    ctx.on_cleanup(_cleanup_agreement)

    described = transfer.describe_agreement(AgreementId=agreement_id, ServerId=server_id)["Agreement"]
    assert described["Status"] == "INACTIVE", f"expected INACTIVE right after create, got {described['Status']!r}"

    transfer.update_agreement(AgreementId=agreement_id, ServerId=server_id, Status="ACTIVE")

    activated = _poll_until(
        lambda: transfer.describe_agreement(AgreementId=agreement_id, ServerId=server_id)["Agreement"],
        lambda a: a["Status"] == "ACTIVE",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert activated["Status"] == "ACTIVE", f"expected ACTIVE after UpdateAgreement, got {activated['Status']!r}"

    transfer.delete_agreement(AgreementId=agreement_id, ServerId=server_id)
    deleted["v"] = True

    error = _client_error(
        lambda: transfer.describe_agreement(AgreementId=agreement_id, ServerId=server_id)
    )
    assert error == ("ResourceNotFoundException", "Unknown agreement"), error

    update_error = _client_error(
        lambda: transfer.update_agreement(AgreementId=agreement_id, ServerId=server_id, Status="ACTIVE")
    )
    assert update_error == ("ResourceNotFoundException", "Unknown agreement"), update_error

    listed = transfer.list_agreements(ServerId=server_id)["Agreements"]
    assert all(a["AgreementId"] != agreement_id for a in listed), (
        f"deleted agreement {agreement_id} still present in ListAgreements"
    )


def _vpc_subnet(ctx):
    """Prefer an existing shared network (nothing to tear down); only provision a fresh
    VPC/subnet when the account has none, so the common case never has to wait out
    the Transfer VPC-endpoint ENI's asynchronous release before DeleteSubnet/DeleteVpc."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if subnets:
            return vpc_id, subnets[0]["SubnetId"]
    return _create_vpc_subnet(ctx)


def _create_vpc_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.212.0.0/24")["Vpc"]["VpcId"]
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.212.0.0/25")["Subnet"]["SubnetId"]

    def _teardown_vpc():
        _wait_for_no_enis(ec2, subnet_id)
        ec2.delete_subnet(SubnetId=subnet_id)
        ec2.delete_vpc(VpcId=vpc_id)

    ctx.on_cleanup(_teardown_vpc)
    return vpc_id, subnet_id


def _wait_for_no_enis(ec2, subnet_id, timeout_s=45.0, interval_s=3.0):
    """The Transfer VPC endpoint's ENI detaches asynchronously after DeleteServer;
    bound the wait so DeleteSubnet/DeleteVpc are not attempted while it is still attached."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            return
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a target
    that accepts what AWS refuses cannot read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


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


def _retry_role_propagation(fn, attempts: int = 6, delay_s: float = 3.0):
    """Retry a call that depends on a just-created IAM role, tolerating IAM's eventual consistency."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


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
