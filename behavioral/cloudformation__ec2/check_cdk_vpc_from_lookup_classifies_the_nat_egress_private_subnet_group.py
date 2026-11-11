"""cdk-vpc-from-lookup-classifies-the-nat-egress-private-subnet-group."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-vpc-from-lookup-classifies-the-nat-egress-private-subnet-group"
GROUP = "deploy-cdk-context-provider"
SERVICES = ["cloudformation", "ec2"]

# The two NAT gateways make teardown the expensive half.
_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 480.0
_SYNTH_TIMEOUT_S = 120.0
_TEARDOWN_DEADLINE_S = 600.0

_TARGET_APP = Path(__file__).parent / "deployments" / "cdk-vpc-l2-defaults"
_LOOKUP_APP = Path(__file__).parent / "deployments" / "cdk-vpc-from-lookup"
_NOT_FOUND_MARKER = "Could not find any VPCs matching"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Vpc.from_lookup classifies a deployed VPC's NAT-egress subnets as Private (route tables, AZs
    match EC2), a lookup matching no VPC fails synth with the not-found error and writes no VPC id,
    and a re-run with the real tag reproduces the first resolution exactly.
    """
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")

    for app in (_TARGET_APP, _LOOKUP_APP):
        assert (app / "app.py").is_file() and (app / "cdk.json").is_file(), (
            f"a CDK app this check needs is missing from disk: expected app.py and cdk.json under "
            f"{app}, found "
            f"{sorted(p.name for p in app.iterdir()) if app.is_dir() else 'no such dir'}"
        )

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdklkt-")
    probe_stack = ctx.unique_name("sim2real-cdklkp-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    # Unique per run, so two concurrent runs cannot resolve each other's VPC.
    tag_value = ctx.unique_name("cdklookup-")
    absent_value = ctx.unique_name("cdklookup-absent-")

    target_work = _stage(ctx, _TARGET_APP, "sim2real-cdklkt-")
    lookup_work = _stage(ctx, _LOOKUP_APP, "sim2real-cdklkp-")
    state: dict[str, Any] = {"vpc": None}

    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, (
        f"this region reports {len(azs)} available AZs ({azs!r}); the target app's max_azs=2 needs "
        f"two for a two-NAT Private group to exist at all"
    )
    want_azs = azs[:2]

    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    _bootstrap(ctx, qualifier, toolkit)

    _cdk(ctx, target_work, ["deploy", "--require-approval", "never",
                            "--outputs-file", "out.json"],
         qualifier, stack, tag_value, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((target_work / "out.json").read_text())[stack]
    vpc_id = outputs["VpcId"]
    state["vpc"] = vpc_id
    deployed_public = sorted(outputs["PublicSubnetIds"].split(","))
    deployed_private = sorted(outputs["PrivateSubnetIds"].split(","))
    assert len(deployed_private) == 2 and len(deployed_public) == 2, (
        f"the deployed stack reported {len(deployed_public)} public and "
        f"{len(deployed_private)} private subnets; the lookup under test needs two of each"
    )

    # Ground truth from EC2 describes, never from anything CDK reported.
    truth = _measure_estate(ec2, vpc_id, deployed_public, deployed_private)
    assert len(truth["nats"]) == 2, (
        f"the deployed VPC {vpc_id!r} has NAT gateways {sorted(truth['nats'])!r}; the Private "
        f"subnet classification under test requires the two the per-AZ default creates"
    )

    _clear_assembly(lookup_work)
    _cdk(ctx, lookup_work, ["synth"], qualifier, probe_stack, tag_value,
         timeout_s=_SYNTH_TIMEOUT_S, expect_rc=0)
    good_context = json.loads((lookup_work / "cdk.context.json").read_text())

    vpc_keys = [k for k in good_context if k.startswith("vpc-provider:")]
    assert len(vpc_keys) == 1, (
        f"cdk.context.json holds vpc-provider keys {vpc_keys!r}, expected exactly one - a "
        f"tag-filtered lookup matching one VPC must write one entry"
    )
    found = good_context[vpc_keys[0]]
    assert found["vpcId"] == vpc_id, (
        f"the lookup resolved vpcId {found['vpcId']!r}, expected the deployed {vpc_id!r}"
    )
    assert found["vpcCidrBlock"] == "10.63.0.0/16", (
        f"the lookup resolved vpcCidrBlock {found['vpcCidrBlock']!r}, expected the app's "
        f"'10.63.0.0/16'"
    )
    assert found["ownerAccountId"] == acct, (
        f"the lookup resolved ownerAccountId {found['ownerAccountId']!r}, expected {acct!r}"
    )

    # CDK classifies Private by a 0.0.0.0/0 route whose target is a nat- id.
    groups = {g["type"]: g for g in found["subnetGroups"]}
    assert sorted(groups) == ["Private", "Public"], (
        f"the lookup partitioned {vpc_id!r} into subnet-group types {sorted(groups)!r}; two "
        f"route tables carrying 0.0.0.0/0 -> {sorted(truth['nats'])!r} and two carrying "
        f"0.0.0.0/0 -> {truth['igw']!r} must yield exactly ['Private', 'Public']. An 'Isolated' "
        f"group here means the NAT route was not seen"
    )
    assert {s["subnetId"] for s in groups["Private"]["subnets"]} == set(deployed_private), (
        f"the Private group holds "
        f"{sorted(s['subnetId'] for s in groups['Private']['subnets'])!r}, expected the two "
        f"NAT-egress subnets {deployed_private!r}"
    )
    assert {s["subnetId"] for s in groups["Public"]["subnets"]} == set(deployed_public), (
        f"the Public group holds "
        f"{sorted(s['subnetId'] for s in groups['Public']['subnets'])!r}, expected "
        f"{deployed_public!r}"
    )

    for gtype, members in (("Private", deployed_private), ("Public", deployed_public)):
        by_subnet = {s["subnetId"]: s for s in groups[gtype]["subnets"]}
        for sid in members:
            assert by_subnet[sid]["routeTableId"] == truth["rtb"][sid], (
                f"the lookup reports subnet {sid!r} ({gtype}) on route table "
                f"{by_subnet[sid]['routeTableId']!r}, but DescribeRouteTables independently "
                f"associates it with {truth['rtb'][sid]!r}"
            )
            assert by_subnet[sid]["availabilityZone"] == truth["az"][sid], (
                f"the lookup reports subnet {sid!r} ({gtype}) in AZ "
                f"{by_subnet[sid]['availabilityZone']!r}, but DescribeSubnets reports "
                f"{truth['az'][sid]!r}"
            )
        assert sorted(by_subnet[s]["availabilityZone"] for s in members) == want_azs, (
            f"the {gtype} group's subnets resolved to AZs "
            f"{sorted(by_subnet[s]['availabilityZone'] for s in members)!r}, expected "
            f"{want_azs!r}"
        )

    # A looked-up VPC id reaches the template as a literal; a Ref means nothing was resolved.
    good_template = json.loads(
        (lookup_work / "cdk.out" / f"{probe_stack}.template.json").read_text())
    sg_vpc = _sg_vpc_id(good_template)
    assert sg_vpc == vpc_id, (
        f"the synthesized SecurityGroup's VpcId is {sg_vpc!r}, expected the literal real id "
        f"{vpc_id!r}; a Ref or a token means the lookup did not resolve"
    )
    egress = sorted(good_template["Outputs"]["EgressSubnetIds"]["Value"].split(","))
    assert egress == deployed_private, (
        f"select_subnets(PRIVATE_WITH_EGRESS) resolved to {egress!r}, expected the deployed "
        f"NAT-egress subnets {deployed_private!r}"
    )
    pub_out = sorted(good_template["Outputs"]["PublicSubnetIds"]["Value"].split(","))
    assert pub_out == deployed_public, (
        f"select_subnets(PUBLIC) resolved to {pub_out!r}, expected {deployed_public!r}"
    )

    # A tag no VPC carries can never become valid, so there is no restore leg.
    _clear_assembly(lookup_work)
    rc, out = _cdk(ctx, lookup_work, ["synth"], qualifier, probe_stack, absent_value,
                   timeout_s=_SYNTH_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk synth` exited {rc} for a lookup filtered on sim2real={absent_value!r}, which no "
        f"VPC in this account carries; the context provider must fail with exit 1. Output "
        f"tail: {out[-600:]!r}"
    )
    assert _NOT_FOUND_MARKER in out, (
        f"the synth failed but not with the documented not-found error {_NOT_FOUND_MARKER!r}; "
        f"any other failure means the check cannot tell 'found nothing' from 'could not look'. "
        f"Output tail: {out[-800:]!r}"
    )
    assert absent_value in out, (
        f"the not-found error does not name the tag value {absent_value!r} that failed to "
        f"match, so an operator cannot see what was searched for. Output tail: {out[-800:]!r}"
    )
    denied_context = json.loads((lookup_work / "cdk.context.json").read_text())
    assert [k for k in denied_context if k.startswith("vpc-provider:")] == [], (
        f"a vpc-provider context entry was written for a lookup that matched no VPC: "
        f"{sorted(denied_context)!r} - a lookup result must never be fabricated"
    )

    # Proves the negative failure came from the tag value, not from state it left behind.
    _clear_assembly(lookup_work)
    _cdk(ctx, lookup_work, ["synth"], qualifier, probe_stack, tag_value,
         timeout_s=_SYNTH_TIMEOUT_S, expect_rc=0)
    again = json.loads((lookup_work / "cdk.context.json").read_text())
    assert again == good_context, (
        f"control: re-running the lookup with the original tag value resolved to "
        f"{json.dumps(again)[:300]!r}, which differs from the first resolution - the tag value "
        f"was supposed to be the only difference between the arms"
    )
    assert _sg_vpc_id(json.loads(
        (lookup_work / "cdk.out" / f"{probe_stack}.template.json").read_text())) == vpc_id, (
        f"control: the re-synthesized template does not carry the real VPC id {vpc_id!r}"
    )
def _stage(ctx, app_dir: Path, prefix: str) -> Path:
    """Copy an on-disk CDK app to a temp workdir so cdk.out, cdk.context.json and out.json never
    land in the source tree."""
    work = Path(tempfile.mkdtemp(prefix=prefix))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _error_code(fn) -> str:
    """The AWS error code a call raises; raises itself when the call succeeds, so a success never
    reads as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"])
    raise AssertionError("call succeeded but was expected to be refused")


def _clear_assembly(work: Path) -> None:
    """Force the next synth to perform the lookup again rather than reading its own cache, and stop
    a stale template or context file from an earlier arm reading as this arm's result."""
    (work / "cdk.context.json").write_text("{}")
    shutil.rmtree(work / "cdk.out", ignore_errors=True)


def _sg_vpc_id(template: dict[str, Any]) -> str:
    sgs = [v for v in template["Resources"].values() if v["Type"] == "AWS::EC2::SecurityGroup"]
    assert len(sgs) == 1, (
        f"the lookup app's template has {len(sgs)} security groups, expected exactly 1"
    )
    return str(sgs[0]["Properties"]["VpcId"])


def _measure_estate(ec2, vpc_id: str, public: list[str], private: list[str]) -> dict[str, Any]:
    """Per-subnet AZ and route table, NAT gateway ids and IGW id, measured via EC2 describes only.

    Asserts the route shapes exist so a mis-deployed estate fails here, not in a later comparison.
    """
    subnets = ec2.describe_subnets(SubnetIds=sorted(public + private))["Subnets"]
    assert len(subnets) == len(public) + len(private), (
        f"DescribeSubnets returned {len(subnets)} of the {len(public) + len(private)} subnets the "
        f"stack reported"
    )
    az = {s["SubnetId"]: s["AvailabilityZone"] for s in subnets}

    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    rtb: dict[str, str] = {}
    for sid in public + private:
        hits = [t for t in tables
                if any(a.get("SubnetId") == sid for a in t.get("Associations", []))]
        assert len(hits) == 1, (
            f"subnet {sid!r} has {len(hits)} explicitly associated route tables "
            f"({[t['RouteTableId'] for t in hits]!r}); CDK associates exactly one per subnet, and "
            f"an unassociated subnet silently inherits the VPC main table instead"
        )
        rtb[sid] = hits[0]["RouteTableId"]

    nats: list[str] = []
    for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filter=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        nats.extend(n["NatGatewayId"] for n in page["NatGateways"]
                    if n["State"] not in ("deleted", "deleting", "failed"))

    igws = ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
    assert len(igws) == 1, (
        f"{len(igws)} internet gateways are attached to {vpc_id!r}; ec2.Vpc creates exactly one"
    )

    # The route shapes the Private/Public classification depends on must really be there.
    for sid in private:
        routes = [r for r in _table(tables, rtb[sid])["Routes"]
                  if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
        assert len(routes) == 1 and routes[0].get("NatGatewayId") in nats, (
            f"private subnet {sid!r}'s route table {rtb[sid]!r} does not carry exactly one "
            f"0.0.0.0/0 route to one of this VPC's NAT gateways {nats!r}; routes seen: {routes!r}. "
            f"Without it there is no Private group for the lookup to find"
        )
    for sid in public:
        routes = [r for r in _table(tables, rtb[sid])["Routes"]
                  if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
        assert len(routes) == 1 and routes[0].get("GatewayId") == igws[0]["InternetGatewayId"], (
            f"public subnet {sid!r}'s route table {rtb[sid]!r} does not carry exactly one "
            f"0.0.0.0/0 route to {igws[0]['InternetGatewayId']!r}; routes seen: {routes!r}"
        )

    return {"az": az, "rtb": rtb, "nats": sorted(nats),
            "igw": igws[0]["InternetGatewayId"]}


def _table(tables: list[dict[str, Any]], rtb_id: str) -> dict[str, Any]:
    hits = [t for t in tables if t["RouteTableId"] == rtb_id]
    assert len(hits) == 1, f"route table {rtb_id!r} appears {len(hits)} times in DescribeRouteTables"
    return hits[0]


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    r = subprocess.run(
        ["cdk", "bootstrap", f"aws://{acct}/{ctx.region}", "--qualifier", qualifier,
         "--toolkit-stack-name", toolkit,
         # AWS_MANAGED_KEY explicitly: an EMPTY value fires the bootstrap template's CreateNewKey
         # condition and mints a customer CMK with a 7-day irreversible deletion window.
         "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci"],
        cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, tag_value: str, *,
         timeout_s: float, expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI against a staged app. `tag_value` is both the CHECK_ID the target app tags
    with and the VPC_TAG_VALUE the lookup filters on, so the arms differ in nothing else."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = tag_value
    env["VPC_TAG_VALUE"] = tag_value
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _stack_status(cfn, stack: str) -> str | None:
    try:
        return str(cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"])
    except ClientError as exc:
        if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
            raise
        return None


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 540.0) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        # The first read after DeleteStack may still show the prior status, so only the two
        # terminal delete states end the poll.
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} is {status!r} after DeleteStack, expected DELETE_COMPLETE; the estate "
        f"it created is leaking"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _teardown(ctx, stack: str, staging: str, toolkit: str, qualifier: str,
              state: dict[str, Any]) -> None:
    """Delete the app stack, the staging bucket and the toolkit stack, poll until no remnant is
    left, and raise naming each one that is. The bootstrap template retains the staging bucket, so
    it is deleted here by name.
    """
    errors: list[str] = []
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    for label, fn in (
        (f"target stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        if errors:  # the app stack deletes as the toolkit's exec role: keep the toolkit for it
            raise AssertionError(f"toolkit stack {toolkit} and staging bucket {staging} kept: "
                                 + "; ".join(errors))
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected and raised below, every step still runs
            errors.append(f"{label}: {exc!r}")

    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining: list[str] = ["teardown verification never ran"]
    while time.monotonic() < deadline:
        remaining = []
        for label, name in (("target stack", stack), ("toolkit stack", toolkit)):
            st = _stack_status(cfn, name)
            if st not in ("DELETE_COMPLETE", None):
                remaining.append(f"{label} {st}")
        try:
            s3.head_bucket(Bucket=staging)
            remaining.append(f"staging bucket {staging} still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "404":
                raise
        try:
            ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append("bootstrap version parameter still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
        if state.get("vpc"):
            try:
                ec2.describe_vpcs(VpcIds=[state["vpc"]])
                remaining.append(f"vpc {state['vpc']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                    raise
            live = [n["NatGatewayId"]
                    for page in ec2.get_paginator("describe_nat_gateways").paginate(
                        Filter=[{"Name": "vpc-id", "Values": [state["vpc"]]}])
                    for n in page["NatGateways"]
                    if n["State"] not in ("deleted", "deleting", "failed")]
            if live:
                remaining.append(f"NAT gateways still live and billing: {live!r}")
        roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
                 for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
        if roles:
            remaining.append(f"bootstrap roles {roles!r}")
        if not remaining:
            break
        time.sleep(10.0)
    else:
        errors.append(f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")

    if state.get("vpc") and not errors:
        code = _error_code(lambda: ctx.client("ec2").describe_vpcs(VpcIds=[state["vpc"]]))
        if code != "InvalidVpcID.NotFound":
            errors.append(
                f"after teardown DescribeVpcs({state['vpc']!r}) failed with {code!r}, "
                f"expected 'InvalidVpcID.NotFound'")
    if errors:
        raise AssertionError(f"teardown left resources behind: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
