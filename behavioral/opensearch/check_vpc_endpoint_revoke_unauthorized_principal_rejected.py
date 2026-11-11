"""vpc-endpoint-revoke-unauthorized-principal-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-endpoint-revoke-unauthorized-principal-rejected"
GROUP = "state-machine"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RevokeVpcEndpointAccess for a never-authorized principal succeeds as a no-op and leaves an
    authorized principal listed; revoking that authorized principal then removes it."""
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    # VPC endpoint access calls only support VPC-attached domains; a public domain gets
    # ValidationException regardless of the principal.
    domain_name = _create_vpc_domain(ctx)
    _wait_domain_active(ctx, domain_name, timeout_s=2400.0)

    # Positive control: with an authorized principal listed, the list below is not trivially empty.
    control_account = sts.get_caller_identity()["Account"]
    authorized = aos.authorize_vpc_endpoint_access(DomainName=domain_name, Account=control_account)[
        "AuthorizedPrincipal"
    ]
    assert control_account in authorized["Principal"], authorized
    listed_before = aos.list_vpc_endpoint_access(DomainName=domain_name)["AuthorizedPrincipalList"]
    assert any(control_account in p["Principal"] for p in listed_before), (
        f"control principal {control_account} missing from listing before revoke: {listed_before}"
    )

    never_authorized_account = "111122223333"
    # Revoking a never-authorized principal is a no-op, not ResourceNotFoundException.
    aos.revoke_vpc_endpoint_access(DomainName=domain_name, Account=never_authorized_account)

    listed_after = aos.list_vpc_endpoint_access(DomainName=domain_name)["AuthorizedPrincipalList"]
    assert not any(never_authorized_account in p["Principal"] for p in listed_after), (
        f"never-authorized account {never_authorized_account} appeared after revoke: {listed_after}"
    )
    assert any(control_account in p["Principal"] for p in listed_after), (
        f"revoking an unrelated, never-authorized principal removed the control principal "
        f"{control_account}: {listed_after}"
    )

    # Revoking the control principal must remove it, so the no-op above is not a do-nothing revoke.
    aos.revoke_vpc_endpoint_access(DomainName=domain_name, Account=control_account)
    listed_final = aos.list_vpc_endpoint_access(DomainName=domain_name)["AuthorizedPrincipalList"]
    assert not any(control_account in p["Principal"] for p in listed_final), (
        f"control principal {control_account} still listed after its own revoke: {listed_final}"
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
    """Create a minimal domain in the run's shared network, since VPC endpoint access calls need a
    VPC-attached domain."""
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

