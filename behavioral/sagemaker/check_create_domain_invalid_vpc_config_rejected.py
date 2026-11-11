"""create-domain-invalid-vpc-config-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-domain-invalid-vpc-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDomain accepts SubnetIds outside the declared VpcId synchronously and returns a DomainId;
    the mismatch surfaces asynchronously as Status=Failed, while a self-consistent VPC, subnet and
    security-group pairing reaches InService.
    """
    ec2 = ctx.client("ec2")
    sm = ctx.client("sagemaker")

    vpc_a = _create_vpc_with_subnet(ctx, ec2, "10.191.0.0/24")
    vpc_b = _create_vpc_with_subnet(ctx, ec2, "10.192.0.0/24")

    role_arn = _create_sagemaker_execution_role(ctx)

    bad_domain_name = ctx.unique_name("sim2real-behav-baddom-")
    bad_resp = sm.create_domain(
        DomainName=bad_domain_name,
        AuthMode="IAM",
        AppNetworkAccessType="VpcOnly",
        VpcId=vpc_a["vpc_id"],
        SubnetIds=[vpc_b["subnet_id"]],  # belongs to vpc_b, not the declared vpc_a
        DefaultUserSettings={
            "ExecutionRole": role_arn,
            "SecurityGroups": [vpc_a["default_sg_id"]],
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    bad_domain_id = bad_resp["DomainId"]
    # Registered BEFORE any assertion below runs, so a wrong hypothesis about the
    # terminal status never leaves this domain uncleaned.
    ctx.on_cleanup(lambda: _delete_domain_and_wait(sm, bad_domain_id))

    bad_status = _poll_terminal_status(sm, bad_domain_id, timeout_s=1500.0, interval_s=15.0)
    assert bad_status == "Failed", (
        f"expected the cross-VPC subnet/security-group mismatch to fail domain "
        f"provisioning (Status=Failed), got {bad_status!r}"
    )

    # effect: the mismatched domain never becomes usable
    names_and_status = {
        d["DomainName"]: d["Status"] for d in sm.list_domains().get("Domains", [])
    }
    assert names_and_status.get(bad_domain_name) == "Failed", (
        f"expected {bad_domain_name!r} to list as Failed, got "
        f"{names_and_status.get(bad_domain_name)!r}"
    )

    # positive control: a self-consistent VPC/subnet/security-group pairing succeeds
    good_domain_name = ctx.unique_name("sim2real-behav-gooddom-")
    resp = sm.create_domain(
        DomainName=good_domain_name,
        AuthMode="IAM",
        AppNetworkAccessType="VpcOnly",
        VpcId=vpc_a["vpc_id"],
        SubnetIds=[vpc_a["subnet_id"]],
        DefaultUserSettings={
            "ExecutionRole": role_arn,
            "SecurityGroups": [vpc_a["default_sg_id"]],
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    domain_id = resp["DomainId"]
    ctx.on_cleanup(lambda: _delete_domain_and_wait(sm, domain_id))
    good_status = _poll_terminal_status(sm, domain_id, timeout_s=1500.0, interval_s=15.0)
    assert good_status == "InService", (
        f"expected the consistent VPC/subnet pairing to reach InService, got {good_status!r}"
    )
    desc = sm.describe_domain(DomainId=domain_id)
    assert desc["VpcId"] == vpc_a["vpc_id"], (
        f"expected VpcId {vpc_a['vpc_id']!r}, got {desc['VpcId']!r}"
    )
    assert desc["SubnetIds"] == [vpc_a["subnet_id"]], (
        f"expected SubnetIds {[vpc_a['subnet_id']]!r}, got {desc['SubnetIds']!r}"
    )


# ===== helpers (self-contained) =====
def _poll_terminal_status(sm, domain_id, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sm.describe_domain(DomainId=domain_id)["Status"]
        if status in ("InService", "Failed"):
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"domain {domain_id} did not reach a terminal status within {timeout_s}s "
        f"(last seen {status!r})"
    )


def _create_sagemaker_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-domrole-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_vpc_with_subnet(ctx, ec2, cidr_block):
    tag_spec = lambda resource_type, name: [  # noqa: E731
        {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}
    ]
    vpc_name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr_block,
        TagSpecifications=tag_spec("vpc", vpc_name),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_name = ctx.unique_name("sim2real-behav-subnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr_block,
        TagSpecifications=tag_spec("subnet", subnet_name),
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    default_sg_id = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"][0]["GroupId"]

    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "default_sg_id": default_sg_id}


def _delete_domain_and_wait(sm, domain_id, timeout_s=900.0, interval_s=15.0):
    sm.delete_domain(DomainId=domain_id, RetentionPolicy={"HomeEfsFileSystem": "Delete"})
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.describe_domain(DomainId=domain_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFound":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_id} was not deleted within {timeout_s}s")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaks the VPC
# while the check passes, until the account's VPC quota is exhausted. So wait
# (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits this suite's 900s cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
