"""overly-permissive-vpc-endpoint-update-malformed-sg-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "overly-permissive-vpc-endpoint-update-malformed-sg-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateVpcEndpoint with a malformed security-group identifier (does not match the
    `sg-<hex>` shape EC2 requires) is rejected synchronously with ValidationException rather
    than accepted and left to fail asynchronously during the UPDATING transition.
    """
    ec2 = ctx.client("ec2")
    subnet_id, sg_id = _default_vpc_network(ec2, ctx=ctx)
    if subnet_id is None:
        raise AssertionError(
            "no default VPC/subnet available in this account/region to provision a VPC "
            "endpoint against; would need a dedicated VPC fixture to close."
        )

    client = ctx.client("opensearch")
    domain_name, domain_status = _create_minimal_domain(ctx, subnet_id, sg_id)
    domain_arn = domain_status["ARN"]

    endpoint_id, endpoint = _create_vpc_endpoint(ctx, domain_arn, subnet_id, sg_id)

    malformed_sg = "not-a-security-group!!"
    code, message = _error(
        lambda: client.update_vpc_endpoint(
            VpcEndpointId=endpoint_id,
            VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [malformed_sg]},
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a malformed security-group id, got {code!r}"
    )
    expected_message = f'Invalid id: "{malformed_sg}" (expecting "sg-...")'
    assert message == expected_message, (
        f"expected message {expected_message!r} for a malformed security-group id, got {message!r}"
    )

    # Effect absent: the endpoint's security groups must be untouched.
    unchanged = client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert unchanged["VpcOptions"]["SecurityGroupIds"] == [sg_id], (
        f"security groups changed despite the rejected update: {unchanged['VpcOptions']!r}"
    )

    # Positive control: the identical shape of call, but with the real (valid) security group,
    # is accepted and drives the endpoint back to ACTIVE.
    client.update_vpc_endpoint(
        VpcEndpointId=endpoint_id,
        VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    final = _poll_until(
        lambda: client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0],
        lambda ep: ep["Status"] not in ("UPDATING", "CREATING"),
        timeout_s=900,
        interval_s=15,
    )
    assert final["Status"] == "ACTIVE", f"expected the valid update to land ACTIVE, got {final!r}"
    assert final["VpcOptions"]["SecurityGroupIds"] == [sg_id], (
        f"expected the restored security group to be [{sg_id!r}], got "
        f"{final['VpcOptions']['SecurityGroupIds']!r}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s (last value={value!r})")


def _default_vpc_network(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        return None, None
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        return None, None
    return subnets[0]["SubnetId"], sgs[0]["GroupId"]


def _create_minimal_domain(ctx, subnet_id, sg_id):
    client = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-osd-")
    client.create_domain(
        DomainName=name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
        AccessPolicies=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "es:*",
                        "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
                    }
                ],
            }
        ),
        TagList=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    deadline = time.monotonic() + 1800
    status = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        # DomainProcessingStatus is the authoritative state machine ("Creating" -> "Active");
        # Created/Processing can flip to "not processing" slightly before the domain is
        # actually ready to accept a VPC endpoint, which then 400s with "domain is currently
        # being created".
        processing_status = status.get("DomainProcessingStatus")
        if processing_status is not None:
            if processing_status == "Active":
                return name, status
        elif status.get("Created") and not status.get("Processing"):
            return name, status
        time.sleep(2)
    raise AssertionError(f"domain {name} did not become active within budget: {status}")


def _create_vpc_endpoint(ctx, domain_arn, subnet_id, sg_id):
    client = ctx.client("opensearch")
    resp = client.create_vpc_endpoint(
        DomainArn=domain_arn,
        VpcOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    endpoint_id = resp["VpcEndpoint"]["VpcEndpointId"]
    ctx.on_cleanup(lambda: client.delete_vpc_endpoint(VpcEndpointId=endpoint_id))
    endpoint = _poll_until(
        lambda: client.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0],
        lambda ep: ep["Status"] not in ("CREATING",),
        timeout_s=900,
        interval_s=15,
    )
    assert endpoint["Status"] == "ACTIVE", f"vpc endpoint failed to become ACTIVE: {endpoint!r}"
    return endpoint_id, endpoint


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
