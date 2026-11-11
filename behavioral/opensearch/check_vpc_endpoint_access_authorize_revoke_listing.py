"""vpc-endpoint-access-authorize-revoke-listing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-endpoint-access-authorize-revoke-listing"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An authorized service principal appears in ListVpcEndpointAccess, the general
    DescribeVpcEndpoints/ListVpcEndpoints listings remain well-formed, and the
    principal disappears from ListVpcEndpointAccess after RevokeVpcEndpointAccess."""
    aos = ctx.client("opensearch")

    # AuthorizeVpcEndpointAccess (and RevokeVpcEndpointAccess) are only meaningful for a
    # domain that is itself deployed inside a VPC -- calling them against a public domain
    # returns ValidationException ("Either the domain doesn't exist, it doesn't support
    # VPC endpoint access, ..."), regardless of whether the domain has finished settling.
    #
    # The Account parameter grants a DIFFERENT account access -- the domain owner already
    # has implicit access to their own domain, so authorizing the caller's own account id
    # is not a valid grant and real AWS answers with that same ValidationException. Use the
    # same-account use case the API actually documents: authorizing the OpenSearch UI
    # application service principal.
    domain_name = _create_vpc_domain(ctx)
    _wait_domain_active(ctx, domain_name, timeout_s=2400.0)

    grantee_service = "application.opensearchservice.amazonaws.com"
    authorize_resp = aos.authorize_vpc_endpoint_access(DomainName=domain_name, Service=grantee_service)
    principal = authorize_resp["AuthorizedPrincipal"]
    assert principal.get("PrincipalType"), principal
    assert grantee_service in principal["Principal"], principal

    listed = aos.list_vpc_endpoint_access(DomainName=domain_name)["AuthorizedPrincipalList"]
    assert any(grantee_service in p["Principal"] for p in listed), "authorized principal missing from listing"

    # General VPC endpoint listings must stay well-formed even with no interface
    # endpoint ever created for this domain.
    describe_resp = aos.describe_vpc_endpoints(VpcEndpointIds=["aos-doesnotexist000"])
    assert describe_resp["VpcEndpoints"] == []
    assert len(describe_resp["VpcEndpointErrors"]) == 1
    assert describe_resp["VpcEndpointErrors"][0]["VpcEndpointId"] == "aos-doesnotexist000"

    all_endpoints = aos.list_vpc_endpoints()
    assert "VpcEndpointSummaryList" in all_endpoints

    aos.revoke_vpc_endpoint_access(DomainName=domain_name, Service=grantee_service)

    listed_after = aos.list_vpc_endpoint_access(DomainName=domain_name)["AuthorizedPrincipalList"]
    assert not any(grantee_service in p["Principal"] for p in listed_after), (
        "principal still listed after RevokeVpcEndpointAccess"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_vpc_domain(ctx, engine_version=None):
    """Creates a minimal domain deployed inside the run's shared network --
    AuthorizeVpcEndpointAccess/RevokeVpcEndpointAccess only support VPC-attached domains."""
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-osb2-")
    account_id = sts.get_caller_identity()["Account"]

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet_id = subnets[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    sg_id = sgs[0]["GroupId"]

    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
        }],
    })
    kwargs = dict(
        DomainName=name,
        EngineVersion=engine_version or "OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
        VPCOptions={"SubnetIds": [subnet_id], "SecurityGroupIds": [sg_id]},
    )
    aos.create_domain(**kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name


def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s=2400.0):
    aos = ctx.client("opensearch")

    def probe():
        return aos.describe_domain(DomainName=name)["DomainStatus"]

    def done(s):
        return bool(s.get("Created")) and not s.get("Processing")

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=20.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
