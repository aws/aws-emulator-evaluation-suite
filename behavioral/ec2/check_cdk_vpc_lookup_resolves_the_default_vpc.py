"""cdk-vpc-lookup-resolves-the-default-vpc."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from behavioral_harness import tags

CHECK = "cdk-vpc-lookup-resolves-the-default-vpc"
GROUP = "cdk-context-provider"
SERVICES = ["ec2"]

_SYNTH_TIMEOUT_S = 180.0
_APP = Path(__file__).parent / "deployments" / "cdk-vpc-lookup-default"


@tags("axis:happy-path", "cap:c3", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Vpc.from_lookup(is_default=True) resolves to the account's default VPC: the id, CIDR, VPN
    gateway, per-subnet AZ and route table CDK writes to cdk.context.json match independent EC2
    reads, and a second synth with the context cache cleared resolves the same values."""
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    acct = ctx.account

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check synthesizes is missing from disk: expected app.py and cdk.json "
        f"under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    vpcs = [
        v
        for v in ec2.get_paginator("describe_vpcs")
        .paginate(Filters=[{"Name": "state", "Values": ["available"]}])
        .build_full_result()["Vpcs"]
        if v.get("IsDefault")
    ]
    assert len(vpcs) == 1, (
        f"this account/region reports {len(vpcs)} default VPCs, expected exactly 1; "
        f"Vpc.from_lookup(is_default=True) needs there to be exactly one"
    )
    vpc_id = vpcs[0]["VpcId"]
    vpc_cidr = vpcs[0]["CidrBlock"]

    truth = _measure_default_vpc(ec2, vpc_id)

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-cdkdvpc-")
    work = _stage(ctx, _APP)

    rc, out = _synth(ctx, work, qualifier, stack, acct)
    assert rc == 0, f"`cdk synth` exited {rc}, expected 0. Output tail: {out[-800:]!r}"

    context = json.loads((work / "cdk.context.json").read_text())
    vpc_keys = [k for k in context if k.startswith("vpc-provider:")]
    assert len(vpc_keys) == 1, (
        f"cdk.context.json holds vpc-provider keys {vpc_keys!r}, expected exactly one"
    )
    found = context[vpc_keys[0]]
    assert found["vpcId"] == vpc_id, (
        f"the lookup resolved vpcId {found['vpcId']!r}, expected the default VPC {vpc_id!r}"
    )
    assert found["vpcCidrBlock"] == vpc_cidr, (
        f"the lookup resolved vpcCidrBlock {found['vpcCidrBlock']!r}, expected {vpc_cidr!r}"
    )
    assert found["ownerAccountId"] == acct, (
        f"the lookup resolved ownerAccountId {found['ownerAccountId']!r}, expected {acct!r}"
    )
    gateways = ec2.describe_vpn_gateways(
        Filters=[
            {"Name": "attachment.vpc-id", "Values": [vpc_id]},
            {"Name": "attachment.state", "Values": ["attached"]},
        ]
    )["VpnGateways"]
    want_vgw = [g["VpnGatewayId"] for g in gateways]
    got_vgw = [found["vpnGatewayId"]] if "vpnGatewayId" in found else []
    assert got_vgw == want_vgw, (
        f"the lookup wrote vpnGatewayId {got_vgw!r}, expected {want_vgw!r} from "
        f"DescribeVpnGateways attached to {vpc_id!r}"
    )

    groups = {g["type"]: g for g in found["subnetGroups"]}
    assert set(groups) == set(truth["groups"]), (
        f"the lookup partitioned {vpc_id!r} into subnet-group types {sorted(groups)!r}, expected "
        f"{sorted(truth['groups'])!r} from independent EC2 reads"
    )
    for gtype, expected_ids in truth["groups"].items():
        got_ids = {s["subnetId"] for s in groups[gtype]["subnets"]}
        assert got_ids == expected_ids, (
            f"the {gtype} group holds {sorted(got_ids)!r}, expected {sorted(expected_ids)!r}"
        )
        by_subnet = {s["subnetId"]: s for s in groups[gtype]["subnets"]}
        for sid in expected_ids:
            assert by_subnet[sid]["routeTableId"] == truth["rtb"][sid], (
                f"subnet {sid!r} resolved routeTableId {by_subnet[sid]['routeTableId']!r}, "
                f"DescribeRouteTables independently associates it with {truth['rtb'][sid]!r}"
            )
            assert by_subnet[sid]["availabilityZone"] == truth["az"][sid], (
                f"subnet {sid!r} resolved availabilityZone {by_subnet[sid]['availabilityZone']!r}, "
                f"DescribeSubnets reports {truth['az'][sid]!r}"
            )

    template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    assert template["Outputs"]["VpcId"]["Value"] == vpc_id, (
        f"the synthesized template's VpcId output is "
        f"{template['Outputs']['VpcId']['Value']!r}, expected the literal real id {vpc_id!r}; a "
        f"Ref or token means the lookup did not resolve"
    )
    assert template["Outputs"]["VpcCidr"]["Value"] == vpc_cidr, (
        f"the synthesized template's VpcCidr output is "
        f"{template['Outputs']['VpcCidr']['Value']!r}, expected {vpc_cidr!r}"
    )

    # Control: re-running the lookup (cache cleared) reproduces the same resolution.
    _clear_assembly(work)
    rc2, out2 = _synth(ctx, work, qualifier, stack, acct)
    assert rc2 == 0, f"control: `cdk synth` exited {rc2}, expected 0. Output tail: {out2[-800:]!r}"
    again = json.loads((work / "cdk.context.json").read_text())
    assert again == context, (
        f"control: re-running the default-VPC lookup resolved to "
        f"{json.dumps(again)[:300]!r}, which differs from the first resolution"
    )


def _measure_default_vpc(ec2, vpc_id: str) -> dict[str, Any]:
    """Per-subnet AZ, route table and subnet-group type, from EC2 reads only: the
    aws-cdk:subnet-type tag, else MapPublicIpOnLaunch or an internet-gateway route (Public), else a
    NAT or transit gateway route (Private), else Isolated, the order the CLI's VPC provider uses."""
    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]
    subnets = (
        ec2.get_paginator("describe_subnets")
        .paginate(Filters=vpc_filter)
        .build_full_result()["Subnets"]
    )
    assert subnets, f"default VPC {vpc_id!r} has no subnets to classify"
    az = {s["SubnetId"]: s["AvailabilityZone"] for s in subnets}

    tables = (
        ec2.get_paginator("describe_route_tables")
        .paginate(Filters=vpc_filter)
        .build_full_result()["RouteTables"]
    )
    main = [t for t in tables if any(a.get("Main") for a in t.get("Associations", []))]
    assert len(main) == 1, f"VPC {vpc_id!r} has {len(main)} main route tables, expected exactly 1"
    main_id = main[0]["RouteTableId"]

    rtb: dict[str, str] = {}
    rtb_doc: dict[str, dict[str, Any]] = {t["RouteTableId"]: t for t in tables}
    for sid in az:
        explicit = [
            t["RouteTableId"]
            for t in tables
            if any(a.get("SubnetId") == sid for a in t.get("Associations", []))
        ]
        rtb[sid] = explicit[0] if explicit else main_id

    groups: dict[str, set] = {}
    for s in subnets:
        sid = s["SubnetId"]
        routes = rtb_doc[rtb[sid]]["Routes"]
        tagged = {t["Key"]: t["Value"] for t in s.get("Tags", [])}.get("aws-cdk:subnet-type")
        if tagged:
            gtype = tagged
        elif s.get("MapPublicIpOnLaunch"):
            gtype = "Public"
        elif any(r.get("GatewayId", "").startswith("igw-") for r in routes):
            gtype = "Public"
        elif any(r.get("NatGatewayId") or r.get("TransitGatewayId") for r in routes):
            gtype = "Private"
        else:
            gtype = "Isolated"
        groups.setdefault(gtype, set()).add(sid)

    return {"az": az, "rtb": rtb, "groups": groups}


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and cdk.context.json stay out of the checkout."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkdvpc-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _clear_assembly(work: Path) -> None:
    """Remove the cloud assembly and context cache so the next synth performs the lookup again."""
    shutil.rmtree(work / "cdk.out", ignore_errors=True)
    (work / "cdk.context.json").unlink(missing_ok=True)


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _synth(ctx, work: Path, qualifier: str, stack: str, acct: str) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    cmd = [
        "cdk",
        "synth",
        "--quiet",
        "--ci",
        "--no-version-reporting",
        "--app",
        f"{sys.executable} app.py",
    ]
    timeout_s = _budget_s(ctx, _SYNTH_TIMEOUT_S)
    try:
        r = subprocess.run(
            cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s
        )
    except subprocess.TimeoutExpired:
        if _budget_spent(ctx):
            raise TimeoutError("`cdk synth`: the run budget ended first; not graded") from None
        raise AssertionError(f"`cdk synth` did not finish within {timeout_s}s") from None
    return r.returncode, r.stdout + r.stderr


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
