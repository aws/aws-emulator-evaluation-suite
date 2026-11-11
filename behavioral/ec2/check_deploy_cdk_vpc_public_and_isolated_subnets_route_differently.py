"""deploy-cdk-vpc-public-and-isolated-subnets-route-differently."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cdk-vpc-public-and-isolated-subnets-route-differently"
GROUP = "deploy"
SERVICES = ["ec2"]

_APP = "cdk_vpc_subnets"
_SYNTH_TIMEOUT_S = 180.0
_STACK_TIMEOUT_S = 420.0


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CDK VPC with PUBLIC and PRIVATE_ISOLATED subnet groups across 2 AZs deploys so public
    subnets route 0.0.0.0/0 to the Internet Gateway, isolated ones carry no default route, and the
    two groups sit on different route tables but share the VPC's one default network ACL."""
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    work = _stage_app(ctx, _APP)
    construct_id = "Sim2RealVpcSubnetsStack"
    template = _synth(ctx, work, construct_id, timeout_s=_SYNTH_TIMEOUT_S)

    stack_name = ctx.unique_name("sim2real-behav-cdkvpc-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        OnFailure="DO_NOTHING",
        Tags=[{"Key": "sim2real", "Value": "cdk-vpc-subnets-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))

    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s is not None and s.endswith(("_COMPLETE", "_FAILED")),
        timeout_s=_STACK_TIMEOUT_S,
    )
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, expected CREATE_COMPLETE"

    outputs = _stack_outputs(cfn, stack_name)
    public_ids = outputs["PublicSubnetIds"].split(",")
    isolated_ids = outputs["IsolatedSubnetIds"].split(",")
    assert len(public_ids) == 2, f"expected 2 public subnets, got {public_ids!r}"
    assert len(isolated_ids) == 2, f"expected 2 isolated subnets, got {isolated_ids!r}"

    # A subnet count alone cannot tell public from isolated; kept only as a floor.
    vpc_id = outputs["VpcId"]
    custom_subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    assert len(custom_subnets) >= 4, f"expected >=4 subnets in {vpc_id}, got {len(custom_subnets)}"

    igw = ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
    )["InternetGateways"]
    assert igw, f"expected an Internet Gateway attached to {vpc_id}"
    igw_id = igw[0]["InternetGatewayId"]

    for subnet_id in public_ids:
        default_route = _default_route_target(ec2, subnet_id)
        assert default_route == igw_id, (
            f"public subnet {subnet_id} must route 0.0.0.0/0 to the Internet Gateway {igw_id}, "
            f"found target {default_route!r}"
        )

    for subnet_id in isolated_ids:
        default_route = _default_route_target(ec2, subnet_id)
        assert default_route is None, (
            f"isolated subnet {subnet_id} must carry NO default route at all, found a 0.0.0.0/0 "
            f"route targeting {default_route!r}"
        )

    # The groups must be on different route tables, not one shared table.
    public_rtbs = {_route_table_id_for_subnet(ec2, s) for s in public_ids}
    isolated_rtbs = {_route_table_id_for_subnet(ec2, s) for s in isolated_ids}
    assert not (public_rtbs & isolated_rtbs), (
        f"public and isolated subnets must not share a route table: public={public_rtbs!r} "
        f"isolated={isolated_rtbs!r}"
    )

    # Per-group route tables are not per-group network ACLs: this app declares no NetworkAcl
    # resource, so every subnet of both groups must fall back to the one ACL AWS implicitly
    # creates with the VPC, unlike the routing above which the stack does split by group.
    all_subnet_ids = public_ids + isolated_ids
    nacls = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]
    assert len(nacls) == 1, (
        f"the deployed VPC {vpc_id} owns {len(nacls)} network ACL(s) "
        f"{[n['NetworkAclId'] for n in nacls]!r}; this stack creates no NetworkAcl resource, so "
        f"only the VPC's own implicit default ACL should exist"
    )
    nacl = nacls[0]
    assert nacl["IsDefault"] is True, (
        f"the VPC's only network ACL {nacl['NetworkAclId']} has IsDefault={nacl['IsDefault']!r}, "
        f"expected True"
    )
    acl_of_subnet = {a["SubnetId"]: nacl["NetworkAclId"] for a in nacl["Associations"] if a.get("SubnetId")}
    missing = [s for s in all_subnet_ids if s not in acl_of_subnet]
    assert not missing, (
        f"subnet(s) {missing!r} carry no recorded association with the default network ACL "
        f"{nacl['NetworkAclId']}; every subnet this stack created must be associated with it"
    )
    assert {acl_of_subnet[s] for s in all_subnet_ids} == {nacl["NetworkAclId"]}, (
        f"public and isolated subnets are not all on network ACL {nacl['NetworkAclId']}: "
        f"{ {s: acl_of_subnet[s] for s in all_subnet_ids} !r}; unlike the per-group route tables, "
        f"the default ACL must be shared by every subnet regardless of its group"
    )

    # Delete, then prove the VPC is really gone: an independent read and a mutation on the dead id
    # both fail with the exact not-found error, not merely "the stack says DELETE_COMPLETE".
    _delete_stack_and_wait(ctx, stack_name)
    not_found = ("InvalidVpcID.NotFound", f"The vpc ID '{vpc_id}' does not exist")
    read_got = _error_code(lambda: ec2.describe_vpcs(VpcIds=[vpc_id]))
    assert read_got == not_found, (
        f"after the stack reached DELETE_COMPLETE, DescribeVpcs({vpc_id}) failed with "
        f"{read_got!r}, expected {not_found!r}"
    )
    mutate_got = _error_code(
        lambda: ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "post-delete-probe", "Value": "x"}])
    )
    assert mutate_got == not_found, (
        f"CreateTags on the deleted VPC {vpc_id} failed with {mutate_got!r}, expected "
        f"{not_found!r} - a mutation on a dead id must be refused the same way a read is"
    )


# ===== helpers =====


def _stage_app(ctx, name: str) -> Path:
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), f"the CDK app this check references is missing from disk: {source}"
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _synth(ctx, work: Path, construct_id: str, *, timeout_s: float) -> dict:
    ctx.verify_account_safety()
    out = "out"
    cmd = [
        "cdk", "synth", construct_id, "--output", out, "--quiet",
        "--context", f"stack_name={construct_id}",
        "--ci", "--no-version-reporting", "--no-color",
    ]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    tail = (result.stdout + result.stderr)[-1200:]
    assert result.returncode == 0, f"`cdk synth` failed (rc={result.returncode}): {tail!r}"
    template_path = work / out / f"{construct_id}.template.json"
    assert template_path.is_file(), f"cdk synth produced no template at {template_path}; output: {tail!r}"
    return json.loads(template_path.read_text())


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)
        last = probe()
    return last


def _stack_status(cfn, stack: str):
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError:
        return None


def _stack_outputs(cfn, stack: str) -> dict:
    described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _delete_stack_and_wait(ctx, stack: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
        return
    try:
        _poll_until(lambda: _stack_status(cfn, stack), lambda s: s is None, timeout_s=420.0)
    except AssertionError:
        raise RuntimeError(f"stack {stack!r} did not reach deleted within 420s")


def _error_code(fn) -> tuple[str, str]:
    """The AWS (code, message) a call raises. Raises when the call SUCCEEDS: an unexpected
    success must never read as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err["Message"])
    raise AssertionError("call succeeded but was expected to be refused")


def _route_table_id_for_subnet(ec2, subnet_id: str) -> str:
    assocs = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
    )["RouteTables"]
    assert assocs, f"no route table is associated with subnet {subnet_id}"
    return assocs[0]["RouteTableId"]


def _default_route_target(ec2, subnet_id: str):
    """The GatewayId of the subnet's 0.0.0.0/0 route, or None if it carries no such route."""
    rtb_id = _route_table_id_for_subnet(ec2, subnet_id)
    rtb = ec2.describe_route_tables(RouteTableIds=[rtb_id])["RouteTables"][0]
    for route in rtb["Routes"]:
        if route.get("DestinationCidrBlock") == "0.0.0.0/0":
            return route.get("GatewayId")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
