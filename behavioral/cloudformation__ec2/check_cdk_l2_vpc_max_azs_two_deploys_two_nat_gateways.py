"""cdk-l2-vpc-max-azs-two-deploys-two-nat-gateways."""
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

CHECK = "cdk-l2-vpc-max-azs-two-deploys-two-nat-gateways"
GROUP = "deploy-cdk-l2-vpc"
SERVICES = ["cloudformation", "ec2"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 600.0
_NAT_AVAILABLE_WAIT_S = 300.0
# ---------------------------------------------------------------------------------------------

_APP = Path(__file__).parent / "deployments" / "cdk-vpc-l2-defaults"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`ec2.Vpc(max_azs=2)` with every other default deploys one NAT gateway per AZ, each in that
    AZ's public subnet with its own Elastic IP, and each private route table sends 0.0.0.0/0 to the
    NAT gateway in its own AZ, read through EC2 describes the deploy never called.
    """
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")

    # The referenced artifact must exist on disk. A missing path is an artifact failure, not a
    # missing prerequisite, so it is asserted before anything is created.
    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys is missing from disk: expected app.py and cdk.json under "
        f"{_APP}, found {sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkvpc-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"

    work = _stage(ctx, _APP)
    state: dict[str, Any] = {"vpc": None}

    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    # The expected NAT and subnet counts are DERIVED from the account's own AZ list,
    # not pinned. max_azs is a cap, so CDK builds min(2, region AZ count) AZs. A region with
    # one AZ would legitimately yield one NAT, and pinning 2 would be a fidelity inversion.
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, (
        f"this region reports {len(azs)} available AZs ({azs!r}); max_azs=2 needs at least two "
        f"for the per-AZ NAT default to be observable at all"
    )
    want_azs = azs[:2]
    want_nats = len(want_azs)

    _bootstrap(ctx, qualifier, toolkit)

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    vpc_id = outputs["VpcId"]
    state["vpc"] = vpc_id
    out_public = sorted(outputs["PublicSubnetIds"].split(","))
    out_private = sorted(outputs["PrivateSubnetIds"].split(","))

    # ---- 1. the VPC exists and is the one the stack reported -----------------------------
    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    assert len(vpcs) == 1 and vpcs[0]["State"] == "available", (
        f"DescribeVpcs for the deployed {vpc_id!r} returned {vpcs!r}; expected exactly one VPC "
        f"in state 'available'"
    )
    assert vpcs[0]["CidrBlock"] == "10.63.0.0/16", (
        f"the deployed VPC's CidrBlock is {vpcs[0]['CidrBlock']!r}, expected the app's "
        f"'10.63.0.0/16'"
    )

    # ---- 2. THE HEADLINE: one NAT gateway per AZ, each with its own EIP -------------------
    nats = _wait_for_available_nats(ec2, vpc_id, want_nats)
    assert len(nats) == want_nats, (
        f"the deployed VPC has {len(nats)} NAT gateway(s) "
        f"({sorted(n['NatGatewayId'] for n in nats)!r}); ec2.Vpc(max_azs=2) leaves "
        f"nat_gateways at its per-AZ default, so exactly {want_nats} are required - one for "
        f"each of {want_azs!r}"
    )
    alloc_ids = sorted(a["AllocationId"] for n in nats for a in n["NatGatewayAddresses"])
    assert len(alloc_ids) == want_nats and len(set(alloc_ids)) == want_nats, (
        f"the {want_nats} NAT gateways hold Elastic IP allocations {alloc_ids!r}; each NAT "
        f"must hold exactly one, and no two may share an allocation"
    )
    for n in nats:
        assert n["ConnectivityType"] == "public", (
            f"NAT gateway {n['NatGatewayId']!r} has ConnectivityType "
            f"{n['ConnectivityType']!r}; the CDK default NAT is a public (internet-egress) "
            f"gateway, so 'public' is required"
        )

    # ---- 3. four subnets, split exactly as the stack outputs claim ------------------------
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    by_id = {s["SubnetId"]: s for s in subnets}
    assert len(subnets) == 2 * want_nats, (
        f"the deployed VPC has {len(subnets)} subnets ({sorted(by_id)!r}); max_azs=2 with the "
        f"default subnet_configuration must produce {2 * want_nats} - one public and one "
        f"private in each of {want_azs!r}"
    )
    assert sorted(by_id) == sorted(out_public + out_private), (
        f"DescribeSubnets reports {sorted(by_id)!r} but the stack outputs named public "
        f"{out_public!r} + private {out_private!r}; the deployed estate and the stack's own "
        f"outputs must agree"
    )
    assert set(out_public).isdisjoint(out_private), (
        f"the stack reported subnet ids in BOTH its public {out_public!r} and private "
        f"{out_private!r} outputs; the two groups must be disjoint"
    )
    assert len(out_public) == want_nats and len(out_private) == want_nats, (
        f"the stack reported {len(out_public)} public and {len(out_private)} private subnets; "
        f"expected {want_nats} of each"
    )
    # one public and one private per AZ, and the AZs are the region's first two.
    pub_azs = sorted(by_id[s]["AvailabilityZone"] for s in out_public)
    priv_azs = sorted(by_id[s]["AvailabilityZone"] for s in out_private)
    assert pub_azs == want_azs and priv_azs == want_azs, (
        f"public subnets landed in AZs {pub_azs!r} and private in {priv_azs!r}; each group "
        f"must cover exactly {want_azs!r} once"
    )

    # ---- 4. the public/private split is real, not just a naming convention ------------
    for sid in out_public:
        assert by_id[sid]["MapPublicIpOnLaunch"] is True, (
            f"public subnet {sid!r} has MapPublicIpOnLaunch "
            f"{by_id[sid]['MapPublicIpOnLaunch']!r}, expected True - the CDK PUBLIC subnet "
            f"type sets it"
        )
    for sid in out_private:
        assert by_id[sid]["MapPublicIpOnLaunch"] is False, (
            f"private subnet {sid!r} has MapPublicIpOnLaunch "
            f"{by_id[sid]['MapPublicIpOnLaunch']!r}, expected False"
        )

    # ---- 5. every NAT gateway sits in a PUBLIC subnet of this VPC -------------------------
    nat_subnets = sorted(n["SubnetId"] for n in nats)
    assert set(nat_subnets) <= set(out_public), (
        f"the NAT gateways are in subnets {nat_subnets!r}, which is not a subset of the "
        f"public subnets {out_public!r}; a NAT gateway in a private subnet has no egress path"
    )
    assert len(set(nat_subnets)) == want_nats, (
        f"the {want_nats} NAT gateways share subnets {nat_subnets!r}; the per-AZ default must "
        f"spread them one per public subnet"
    )

    # ---- 6. THE JOIN: private-subnet routes point at the SAME-AZ NAT -----------------
    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    # Every VPC also carries one implicit MAIN route table that AWS creates alongside it and
    # that CDK's per-subnet AWS::EC2::RouteTable resources do not replace or absorb - it is
    # not associated with any subnet, only with the VPC itself. describe_route_tables returns
    # it too, so the subnet-owned tables must be isolated from it before counting either.
    main_tables = [t for t in tables if any(a.get("Main") for a in t.get("Associations", []))]
    subnet_tables = [t for t in tables
                      if any(a.get("SubnetId") for a in t.get("Associations", []))]
    assert len(main_tables) == 1, (
        f"the deployed VPC {vpc_id!r} has {len(main_tables)} implicit main route table(s) "
        f"({[t['RouteTableId'] for t in main_tables]!r}); every VPC gets exactly one, "
        f"distinct from the ones CDK creates and associates per subnet"
    )
    assert len(subnet_tables) == 2 * want_nats, (
        f"the deployed VPC has {len(subnet_tables)} subnet-associated route tables "
        f"({sorted(t['RouteTableId'] for t in subnet_tables)!r}), excluding the implicit "
        f"main table {main_tables[0]['RouteTableId']!r}; CDK gives each of the "
        f"{2 * want_nats} subnets its own, so {2 * want_nats} are required"
    )
    assert len(tables) == len(subnet_tables) + len(main_tables), (
        f"describe_route_tables returned {len(tables)} route table(s) total for {vpc_id!r}, "
        f"but {len(subnet_tables)} subnet-associated plus {len(main_tables)} main account "
        f"for only {len(subnet_tables) + len(main_tables)}; some route table here is neither"
    )
    nat_by_subnet = {n["SubnetId"]: n["NatGatewayId"] for n in nats}
    nat_az = {n["NatGatewayId"]: by_id[n["SubnetId"]]["AvailabilityZone"] for n in nats}
    assert sorted(nat_az.values()) == want_azs, (
        f"the NAT gateways resolved to AZs {sorted(nat_az.values())!r}, expected one in each "
        f"of {want_azs!r}"
    )
    nat_in_az = {az: nat_id for nat_id, az in nat_az.items()}

    for sid in out_private:
        az = by_id[sid]["AvailabilityZone"]
        route = _default_route(tables, sid, vpc_id)
        got_nat = route.get("NatGatewayId")
        assert got_nat == nat_in_az[az], (
            f"private subnet {sid!r} is in AZ {az!r} but routes 0.0.0.0/0 to "
            f"{got_nat!r}, expected {nat_in_az[az]!r}, the NAT gateway in its own AZ; the per-AZ "
            f"NAT default exists so each private subnet egresses through the NAT in its AZ "
            f"(NAT placement: {nat_by_subnet!r})"
        )
        assert route["State"] == "active", (
            f"private subnet {sid!r}'s 0.0.0.0/0 route to {got_nat!r} is in state "
            f"{route['State']!r}, expected 'active' - a blackhole route means the NAT it names "
            f"is not usable"
        )

    # ---- 7. public subnets route to the ONE internet gateway attached to this VPC ---------
    igws = ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
    assert len(igws) == 1, (
        f"{len(igws)} internet gateways are attached to {vpc_id!r} "
        f"({[g['InternetGatewayId'] for g in igws]!r}); ec2.Vpc creates exactly one"
    )
    igw_id = igws[0]["InternetGatewayId"]
    for sid in out_public:
        route = _default_route(tables, sid, vpc_id)
        assert route.get("GatewayId") == igw_id, (
            f"public subnet {sid!r} routes 0.0.0.0/0 to "
            f"{route.get('GatewayId') or route.get('NatGatewayId')!r}, expected the VPC's "
            f"internet gateway {igw_id!r}"
        )
        assert route["State"] == "active", (
            f"public subnet {sid!r}'s 0.0.0.0/0 route to {igw_id!r} is in state "
            f"{route['State']!r}, expected 'active'"
        )

    # ---- 8. no private subnet is reachable from the internet ------------------------------
    # The inverse of 7, asserted structurally rather than by probing: a private subnet's route
    # table must contain NO igw- target at any destination.
    for sid in out_private:
        table = _table_for(tables, sid, vpc_id)
        igw_routes = [r for r in table["Routes"]
                      if str(r.get("GatewayId", "")).startswith("igw-")]
        assert igw_routes == [], (
            f"private subnet {sid!r}'s route table {table['RouteTableId']!r} carries "
            f"internet-gateway routes {igw_routes!r}; a CDK PRIVATE_WITH_EGRESS subnet must "
            f"reach the internet only through a NAT gateway"
        )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the on-disk CDK app to a temp workdir so cdk.out / cdk.context.json / out.json are
    never written next to the check."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkvpc-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _error_code(fn) -> str:
    """The AWS error code a call raises. Raises when the call SUCCEEDS: an unexpected success is the
    strongest possible signal."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"])
    raise AssertionError("call succeeded but was expected to be refused")


def _table_for(tables: list[dict[str, Any]], subnet_id: str, vpc_id: str) -> dict[str, Any]:
    """The route table EXPLICITLY associated with subnet_id. Hard-fails rather than falling back to
    the VPC main table: CDK associates every subnet it creates, so an unassociated subnet is the
    defect, not a case to paper over."""
    hits = [t for t in tables
            if any(a.get("SubnetId") == subnet_id for a in t.get("Associations", []))]
    assert len(hits) == 1, (
        f"subnet {subnet_id!r} in {vpc_id!r} has {len(hits)} explicitly associated route tables "
        f"({[t['RouteTableId'] for t in hits]!r}); CDK associates exactly one per subnet, and an "
        f"unassociated subnet silently inherits the VPC main table instead"
    )
    return hits[0]


def _default_route(tables: list[dict[str, Any]], subnet_id: str, vpc_id: str) -> dict[str, Any]:
    """The 0.0.0.0/0 route of the table associated with subnet_id."""
    table = _table_for(tables, subnet_id, vpc_id)
    hits = [r for r in table["Routes"] if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert len(hits) == 1, (
        f"route table {table['RouteTableId']!r} (subnet {subnet_id!r}) has {len(hits)} routes for "
        f"0.0.0.0/0; expected exactly one. Routes: {table['Routes']!r}"
    )
    return hits[0]


def _nats_in_vpc(ec2, vpc_id: str) -> list[dict[str, Any]]:
    """Every NAT gateway in the VPC that is not already torn down. `deleted`/`failed` gateways stay
    visible for about an hour, so filtering them out here is what makes the count assertion mean
    'live NAT gateways' rather than 'NAT gateway records'."""
    found: list[dict[str, Any]] = []
    for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filter=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        found.extend(n for n in page["NatGateways"]
                     if n["State"] not in ("deleted", "deleting", "failed"))
    return found


def _wait_for_available_nats(ec2, vpc_id: str, want: int) -> list[dict[str, Any]]:
    """Bounded retry until `want` NAT gateways in the VPC report State == 'available'.

    It RAISES on timeout rather than returning what it last saw, so a NAT gateway left pending
    forever cannot pass.
    """
    deadline = time.monotonic() + _NAT_AVAILABLE_WAIT_S
    seen: list[dict[str, Any]] = []
    while True:
        seen = _nats_in_vpc(ec2, vpc_id)
        ready = [n for n in seen if n["State"] == "available"]
        if len(ready) >= want:
            return ready
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"after {_NAT_AVAILABLE_WAIT_S}s only {len(ready)} of {want} NAT gateways in "
                f"{vpc_id!r} report State == 'available'; states seen: "
                f"{ {n['NatGatewayId']: n['State'] for n in seen} !r}"
            )
        time.sleep(2.0)


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


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    # --app overrides cdk.json's interpreter-agnostic "python3 app.py" with the interpreter that
    # actually has aws-cdk-lib importable; cdk.json keeps the plain form so the app synthesizes
    # standalone for anyone inspecting deployments/.
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


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
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    for label, fn in (
        (f"app stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
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
        try:
            st = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"app stack {st}")
        except ClientError as exc:
            if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
                raise
        try:
            st = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {st}")
        except ClientError as exc:
            if exc.response["Error"]["Message"] != f"Stack with id {toolkit} does not exist":
                raise
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
            # NAT gateways stay VISIBLE in `deleted` state for about an hour, so absence here
            # is "no live NAT gateway", not "no record".
            live = _nats_in_vpc(ec2, state["vpc"])
            if live:
                remaining.append(
                    f"NAT gateways still live: { {n['NatGatewayId']: n['State'] for n in live} !r}")
        roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
                 for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
        if roles:
            remaining.append(f"bootstrap roles {roles!r}")
        if not remaining:
            break
        time.sleep(10.0)
    else:
        errors.append(
            f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")

    # The VPC this check created is confirmed gone by its own not-found code.
    if state.get("vpc") and not errors:
        code = _error_code(lambda: ctx.client("ec2").describe_vpcs(VpcIds=[state["vpc"]]))
        if code != "InvalidVpcID.NotFound":
            errors.append(
                f"after teardown DescribeVpcs({state['vpc']!r}) failed with {code!r}, "
                f"expected 'InvalidVpcID.NotFound'")
    if errors:
        raise AssertionError(f"teardown failed to converge: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
