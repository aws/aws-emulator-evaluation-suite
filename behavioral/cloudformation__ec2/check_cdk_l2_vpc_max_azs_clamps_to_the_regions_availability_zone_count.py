"""cdk-l2-vpc-max-azs-clamps-to-the-regions-availability-zone-count."""
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

CHECK = "cdk-l2-vpc-max-azs-clamps-to-the-regions-availability-zone-count"
GROUP = "deploy-cdk-l2-vpc"
SERVICES = ["cloudformation", "ec2"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 600.0
_NAT_AVAILABLE_WAIT_S = 300.0
# ---------------------------------------------------------------------------------------------

_APP = Path(__file__).parent / "deployments" / "cdk-vpc-maxazs-clamp"

# How far past the region's real zone count to ask for. Any value > N makes the clamp observable;
# 5 is comfortably beyond every current region without being an absurd number that a target might
# special-case.
_OVERSHOOT = 5


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`ec2.Vpc(max_azs=N+5)` clamps to the N availability zones the account has in the region
    (read from `describe_availability_zones`): 2*N subnets, 2*N+1 route tables, and every private
    subnet routes 0.0.0.0/0 to the app's single NAT gateway.
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
    stack = ctx.unique_name("sim2real-cdkazs-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"

    work = _stage(ctx, _APP)
    state: dict[str, Any] = {"vpc": None}

    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    # N comes from the account, and the request is deliberately unsatisfiable.
    region_azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    want_n = len(region_azs)
    assert want_n >= 2, (
        f"this region reports {want_n} available AZs ({region_azs!r}); the clamp is only "
        f"observable with at least two, because a one-zone region cannot distinguish 'clamped "
        f"to the region's count' from 'ignored max_azs entirely'"
    )
    asked_for = want_n + _OVERSHOOT

    _bootstrap(ctx, qualifier, toolkit)

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, asked_for, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    vpc_id = outputs["VpcId"]
    state["vpc"] = vpc_id
    out_public = sorted(outputs["PublicSubnetIds"].split(","))
    out_private = sorted(outputs["PrivateSubnetIds"].split(","))

    # ---- 1. the clamp, as the construct itself reports it --------------------------------
    assert outputs["AzCount"] == str(want_n), (
        f"the app asked for max_azs={asked_for} and the stack's AzCount output is "
        f"{outputs['AzCount']!r}; this account sees {want_n} available AZs in {ctx.region!r} "
        f"({region_azs!r}), so max_azs must clamp to {want_n}. A value of "
        f"{str(asked_for)!r} means the cap was ignored; '3' in a region with "
        f"{want_n} zones means a hardcoded default was used instead of the real zone list"
    )

    # ---- 2. the VPC exists and is the one the stack reported ------------------------------
    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    assert len(vpcs) == 1 and vpcs[0]["State"] == "available", (
        f"DescribeVpcs for the deployed {vpc_id!r} returned {vpcs!r}; expected exactly one VPC "
        f"in state 'available'"
    )
    assert vpcs[0]["CidrBlock"] == "10.66.0.0/16", (
        f"the deployed VPC's CidrBlock is {vpcs[0]['CidrBlock']!r}, expected the app's "
        f"'10.66.0.0/16'"
    )

    # ---- 3. the deployed subnet fan-out is 2*N, split exactly as the outputs claim --------
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    by_id = {s["SubnetId"]: s for s in subnets}
    assert len(subnets) == 2 * want_n, (
        f"the deployed VPC has {len(subnets)} subnets ({sorted(by_id)!r}); a clamp to "
        f"{want_n} AZs with the default subnet_configuration must produce {2 * want_n} - one "
        f"public and one private per zone. {2 * asked_for} would mean max_azs={asked_for} was "
        f"honoured"
    )
    assert len(out_public) == want_n and len(out_private) == want_n, (
        f"the stack reported {len(out_public)} public and {len(out_private)} private subnets, "
        f"expected {want_n} of each after the clamp to {region_azs!r}"
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

    # ---- 4. the real per-account zone NAMES, as a set, one pair per zone ------------------
    pub_azs = sorted(by_id[s]["AvailabilityZone"] for s in out_public)
    priv_azs = sorted(by_id[s]["AvailabilityZone"] for s in out_private)
    assert pub_azs == region_azs, (
        f"the public subnets landed in AZs {pub_azs!r}, expected exactly the region's "
        f"available zones {region_azs!r}, once each. AZ names are per-account aliases, so a "
        f"target serving a hardcoded zone list diverges here even when the COUNT matches"
    )
    assert priv_azs == region_azs, (
        f"the private subnets landed in AZs {priv_azs!r}, expected exactly the region's "
        f"available zones {region_azs!r}, once each"
    )

    # ---- 5. public/private is a real attribute difference, not a naming convention --------
    for sid in out_public:
        assert by_id[sid]["MapPublicIpOnLaunch"] is True, (
            f"public subnet {sid!r} (AZ {by_id[sid]['AvailabilityZone']!r}) has "
            f"MapPublicIpOnLaunch {by_id[sid]['MapPublicIpOnLaunch']!r}, expected True - the "
            f"CDK PUBLIC subnet type sets it"
        )
    for sid in out_private:
        assert by_id[sid]["MapPublicIpOnLaunch"] is False, (
            f"private subnet {sid!r} (AZ {by_id[sid]['AvailabilityZone']!r}) has "
            f"MapPublicIpOnLaunch {by_id[sid]['MapPublicIpOnLaunch']!r}, expected False"
        )

    # ---- 6. one explicit route table per subnet (2*N), plus the VPC's own implicit main
    # table: every VPC carries exactly one main route table AWS creates automatically at VPC
    # creation, on top of whatever route tables CDK explicitly associates to subnets, so the
    # honest count is 2*N+1, not 2*N. Pinning "+1" is safe: it is a structural fact about how
    # every VPC is built, identical in every account and region, not a value that could vary
    # like the AZ count does.
    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    main_tables = [t for t in tables
                   if any(a.get("Main") for a in t.get("Associations", []))]
    assert len(main_tables) == 1, (
        f"the deployed VPC has {len(main_tables)} route table(s) flagged as the VPC main table "
        f"({[t['RouteTableId'] for t in main_tables]!r}) among {sorted(t['RouteTableId'] for t in tables)!r}; "
        f"AWS creates exactly one implicit main route table per VPC, separate from the "
        f"{2 * want_n} explicit ones CDK associates to subnets"
    )
    assert len(tables) == 2 * want_n + 1, (
        f"the deployed VPC has {len(tables)} route tables "
        f"({sorted(t['RouteTableId'] for t in tables)!r}); CDK gives each of the "
        f"{2 * want_n} subnets its own explicit route table, and the VPC additionally carries "
        f"its own implicit main route table {main_tables[0]['RouteTableId']!r}, so "
        f"{2 * want_n + 1} are required. {2 * want_n} would mean the implicit main table was "
        f"mistaken for absent"
    )

    # ---- 7. exactly one NAT gateway, and every private subnet egresses through it ---------
    nats = _wait_for_available_nats(ec2, vpc_id, 1)
    assert len(nats) == 1, (
        f"the deployed VPC has {len(nats)} available NAT gateway(s) "
        f"({sorted(n['NatGatewayId'] for n in nats)!r}); the app pins nat_gateways=1, so "
        f"exactly one is required no matter how many zones the VPC spans"
    )
    nat = nats[0]
    nat_id = nat["NatGatewayId"]
    assert nat["SubnetId"] in set(out_public), (
        f"NAT gateway {nat_id!r} is in subnet {nat['SubnetId']!r}, which is not one of the "
        f"public subnets {out_public!r}; a NAT gateway in a private subnet has no egress path"
    )
    alloc_ids = sorted(a["AllocationId"] for a in nat["NatGatewayAddresses"])
    assert len(alloc_ids) == 1, (
        f"NAT gateway {nat_id!r} holds Elastic IP allocations {alloc_ids!r}, expected exactly "
        f"one"
    )
    nat_az = by_id[nat["SubnetId"]]["AvailabilityZone"]

    for sid in out_private:
        az = by_id[sid]["AvailabilityZone"]
        route = _default_route(tables, sid, vpc_id)
        got_nat = route.get("NatGatewayId")
        assert got_nat == nat_id, (
            f"private subnet {sid!r} (AZ {az!r}) routes 0.0.0.0/0 to {got_nat!r}, expected the "
            f"VPC's single NAT gateway {nat_id!r} (which lives in AZ {nat_az!r}). With "
            f"nat_gateways=1 every private subnet shares one NAT, so {want_n - 1} of the "
            f"{want_n} private subnets egress cross-AZ by design"
        )
        assert route["State"] == "active", (
            f"private subnet {sid!r}'s 0.0.0.0/0 route to {nat_id!r} is in state "
            f"{route['State']!r}, expected 'active' - a blackhole route means the NAT it names "
            f"is not usable"
        )

    # ---- 8. every public subnet routes to the ONE internet gateway of this VPC ------------
    igws = ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
    assert len(igws) == 1, (
        f"{len(igws)} internet gateways are attached to {vpc_id!r} "
        f"({[g['InternetGatewayId'] for g in igws]!r}); ec2.Vpc creates exactly one however "
        f"many zones it spans"
    )
    igw_id = igws[0]["InternetGatewayId"]
    for sid in out_public:
        route = _default_route(tables, sid, vpc_id)
        assert route.get("GatewayId") == igw_id, (
            f"public subnet {sid!r} (AZ {by_id[sid]['AvailabilityZone']!r}) routes 0.0.0.0/0 "
            f"to {route.get('GatewayId') or route.get('NatGatewayId')!r}, expected the VPC's "
            f"internet gateway {igw_id!r}"
        )
        assert route["State"] == "active", (
            f"public subnet {sid!r}'s 0.0.0.0/0 route to {igw_id!r} is in state "
            f"{route['State']!r}, expected 'active'"
        )
# ===== helpers =====


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the on-disk CDK app to a temp workdir so cdk.out / cdk.context.json / out.json are
    never written into the source checkout."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkazs-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _error_code(fn) -> str:
    """The AWS error code a call raises. Raises when the call SUCCEEDS: an unexpected success is
    the strongest possible signal and must never be turned into a code mismatch."""
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


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, max_azs: int, *,
         timeout_s: float, expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    env["MAX_AZS"] = str(max_azs)
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
        raise AssertionError(f"teardown left resources behind: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
