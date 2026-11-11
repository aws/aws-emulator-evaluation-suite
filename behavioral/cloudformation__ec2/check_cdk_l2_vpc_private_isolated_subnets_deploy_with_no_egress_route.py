"""cdk-l2-vpc-private-isolated-subnets-deploy-with-no-egress-route."""
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

CHECK = "cdk-l2-vpc-private-isolated-subnets-deploy-with-no-egress-route"
GROUP = "deploy-cdk-l2-vpc"
SERVICES = ["cloudformation", "ec2"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 420.0
_TEARDOWN_DEADLINE_S = 420.0
# ---------------------------------------------------------------------------------------------

_APP = Path(__file__).parent / "deployments" / "cdk-vpc-private-isolated"


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`PRIVATE_ISOLATED` subnets deploy with no egress route at all (no 0.0.0.0/0 to a NAT, an
    internet gateway or a blackhole) and no NAT gateway, while the public subnets of the same VPC
    route 0.0.0.0/0 to the attached internet gateway.
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
    stack = ctx.unique_name("sim2real-cdkiso-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    vpc_cidr = "10.65.0.0/16"

    work = _stage(ctx, _APP)
    state: dict[str, Any] = {"vpc": None}

    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    # The expected subnet counts are DERIVED from the account's own AZ list, never
    # pinned. max_azs is a cap, so CDK builds min(2, region AZ count) AZs and one subnet of
    # each configured type per AZ.
    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, (
        f"this region reports {len(azs)} available AZs ({azs!r}); max_azs=2 needs at least two "
        f"for the isolated subnet group to have more than one member"
    )
    want_azs = azs[:2]
    want_per_group = len(want_azs)

    _bootstrap(ctx, qualifier, toolkit)

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    vpc_id = outputs["VpcId"]
    state["vpc"] = vpc_id
    out_public = sorted(outputs["PublicSubnetIds"].split(","))
    out_isolated = sorted(outputs["IsolatedSubnetIds"].split(","))

    # ---- 1. the VPC exists and is the one the stack reported -----------------------------
    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"]
    assert len(vpcs) == 1 and vpcs[0]["State"] == "available", (
        f"DescribeVpcs for the deployed {vpc_id!r} returned {vpcs!r}; expected exactly one VPC "
        f"in state 'available'"
    )
    assert vpcs[0]["CidrBlock"] == vpc_cidr, (
        f"the deployed VPC's CidrBlock is {vpcs[0]['CidrBlock']!r}, expected the app's "
        f"{vpc_cidr!r}"
    )

    # ---- 2. nat_gateways=0 means NO NAT gateway was built at all ---------------------------
    live_nats = _nats_in_vpc(ec2, vpc_id)
    assert live_nats == [], (
        f"the deployed VPC has live NAT gateway(s) "
        f"{ {n['NatGatewayId']: n['State'] for n in live_nats} !r}; this app sets "
        f"nat_gateways=0 and declares only PUBLIC and PRIVATE_ISOLATED subnets, so a NAT "
        f"gateway must never be created - and a target that builds one is also billing for it"
    )

    # ---- 3. no network interfaces, therefore no Elastic IP is associated in this VPC ---
    # Scoped to this VPC deliberately. An account-wide DescribeAddresses sweep would pick up
    # Elastic IPs belonging to concurrent runs and is not this check's blast radius.
    enis = ec2.describe_network_interfaces(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]
    assert enis == [], (
        f"the deployed VPC has {len(enis)} network interface(s) "
        f"({[e['NetworkInterfaceId'] for e in enis]!r}); a VPC of subnets, route tables and an "
        f"internet gateway has none, and since an Elastic IP must be associated with an ENI or "
        f"an instance, zero ENIs is what proves no Elastic IP is attached to anything here"
    )

    # ---- 4. the subnet census: two groups, one subnet of each type per AZ ------------------
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    by_id = {s["SubnetId"]: s for s in subnets}
    assert len(subnets) == 2 * want_per_group, (
        f"the deployed VPC has {len(subnets)} subnets ({sorted(by_id)!r}); a two-entry "
        f"subnet_configuration across {want_azs!r} must produce {2 * want_per_group}"
    )
    assert sorted(by_id) == sorted(out_public + out_isolated), (
        f"DescribeSubnets reports {sorted(by_id)!r} but the stack outputs named public "
        f"{out_public!r} + isolated {out_isolated!r}; the deployed estate and the stack's own "
        f"outputs must agree"
    )
    assert set(out_public).isdisjoint(out_isolated), (
        f"the stack reported subnet ids in BOTH its public {out_public!r} and isolated "
        f"{out_isolated!r} outputs; the two groups must be disjoint"
    )
    assert len(out_public) == want_per_group, (
        f"the stack reported {len(out_public)} public subnets ({out_public!r}), expected "
        f"{want_per_group} - one in each of {want_azs!r}"
    )
    assert len(out_isolated) == want_per_group, (
        f"the stack reported {len(out_isolated)} isolated subnets ({out_isolated!r}), expected "
        f"{want_per_group} - one in each of {want_azs!r}"
    )
    pub_azs = sorted(by_id[s]["AvailabilityZone"] for s in out_public)
    iso_azs = sorted(by_id[s]["AvailabilityZone"] for s in out_isolated)
    assert pub_azs == want_azs and iso_azs == want_azs, (
        f"public subnets landed in AZs {pub_azs!r} and isolated in {iso_azs!r}; each group "
        f"must cover exactly {want_azs!r} once"
    )

    # ---- 5. the public/isolated split is real, not just a naming convention ------------
    for sid in out_public:
        assert by_id[sid]["MapPublicIpOnLaunch"] is True, (
            f"public subnet {sid!r} has MapPublicIpOnLaunch "
            f"{by_id[sid]['MapPublicIpOnLaunch']!r}, expected True - the CDK PUBLIC subnet "
            f"type sets it"
        )
    for sid in out_isolated:
        assert by_id[sid]["MapPublicIpOnLaunch"] is False, (
            f"isolated subnet {sid!r} has MapPublicIpOnLaunch "
            f"{by_id[sid]['MapPublicIpOnLaunch']!r}, expected False - a PRIVATE_ISOLATED "
            f"subnet must not auto-assign public addresses"
        )

    # ---- 6. every subnet gets its own route table, plus the VPC's one implicit main table --
    # Every VPC carries exactly one implicit "main" route table from creation, with no
    # explicit subnet association, in addition to whatever explicit tables get created. CDK
    # associates every subnet it builds with its own explicit table, so the main table stays
    # unassociated and unused, but it is not gone - DescribeRouteTables on the VPC still lists
    # it. This is a property of VPCs, not of CDK's subnet_type, so it is asserted directly
    # rather than folded into the "no egress route" subject.
    tables = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"]
    main_tables = [t for t in tables
                  if any(a.get("Main") for a in t.get("Associations", []))]
    assert len(main_tables) == 1, (
        f"the deployed VPC has {len(main_tables)} main route table(s) "
        f"({[t['RouteTableId'] for t in main_tables]!r}); every VPC carries exactly one "
        f"implicit main route table from creation, regardless of how many explicit ones CDK "
        f"also builds"
    )
    assert len(tables) == 2 * want_per_group + 1, (
        f"the deployed VPC has {len(tables)} route tables "
        f"({sorted(t['RouteTableId'] for t in tables)!r}); CDK gives each of the "
        f"{2 * want_per_group} subnets its own explicit table, plus the one implicit main "
        f"route table every VPC carries, so {2 * want_per_group + 1} are required - having no "
        f"egress route is not the same as having no route table"
    )
    associations = [a for t in tables for a in t.get("Associations", [])
                    if a.get("SubnetId")]
    assert len(associations) == 2 * want_per_group, (
        f"the VPC's route tables carry {len(associations)} explicit subnet associations "
        f"({[(a.get('SubnetId'), a.get('RouteTableId')) for a in associations]!r}); every one "
        f"of the {2 * want_per_group} subnets must be explicitly associated, or it silently "
        f"inherits the VPC main table"
    )

    # ---- 7. POSITIVE CONTROL, same stack, same instant ------------------------------------
    # This runs BEFORE the absence assertions on purpose: until the public subnets are shown to
    # reach the internet gateway, "the isolated subnets have no egress route" is
    # indistinguishable from "a target that creates no routes at all".
    igws = ec2.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])["InternetGateways"]
    assert len(igws) == 1, (
        f"{len(igws)} internet gateways are attached to {vpc_id!r} "
        f"({[g['InternetGatewayId'] for g in igws]!r}); the PUBLIC subnet_configuration entry "
        f"makes ec2.Vpc create exactly one"
    )
    igw_id = igws[0]["InternetGatewayId"]
    for sid in out_public:
        route = _default_route(tables, sid, vpc_id)
        assert route.get("GatewayId") == igw_id, (
            f"positive control failed: public subnet {sid!r} routes 0.0.0.0/0 to "
            f"{route.get('GatewayId') or route.get('NatGatewayId')!r}, expected the VPC's "
            f"internet gateway {igw_id!r}. Until this holds, the isolated subnets' missing "
            f"route proves nothing"
        )
        assert route["State"] == "active", (
            f"positive control failed: public subnet {sid!r}'s 0.0.0.0/0 route to {igw_id!r} "
            f"is in state {route['State']!r}, expected 'active'"
        )

    # ---- 8. THE SUBJECT: the isolated subnets have NO default route of any kind ------------
    for sid in out_isolated:
        table = _table_for(tables, sid, vpc_id)
        rtb = table["RouteTableId"]
        routes = table["Routes"]

        # An equality-to-empty is the correct shape here: the empty case IS the property.
        default_routes = [r for r in routes
                          if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
        assert default_routes == [], (
            f"isolated subnet {sid!r} (route table {rtb!r}) has 0.0.0.0/0 route(s) "
            f"{default_routes!r}; a PRIVATE_ISOLATED subnet must have NO default route at all. "
            f"Note a blackholed default route is also a failure here: it is one CreateRoute "
            f"away from live egress the subnet type forbids"
        )
        nat_routes = [r for r in routes if r.get("NatGatewayId")]
        assert nat_routes == [], (
            f"isolated subnet {sid!r} (route table {rtb!r}) has route(s) targeting a NAT "
            f"gateway: {nat_routes!r}; nat_gateways=0 and PRIVATE_ISOLATED both forbid it"
        )
        igw_routes = [r for r in routes
                      if str(r.get("GatewayId", "")).startswith("igw-")]
        assert igw_routes == [], (
            f"isolated subnet {sid!r} (route table {rtb!r}) has internet-gateway route(s) "
            f"{igw_routes!r}; the VPC's internet gateway {igw_id!r} must be reachable only "
            f"from the public subnets {out_public!r}"
        )

        # The only thing left must be the VPC-local routes AWS creates implicitly.
        non_local = [r for r in routes if r.get("GatewayId") != "local"]
        assert non_local == [], (
            f"isolated subnet {sid!r} (route table {rtb!r}) has route(s) whose target is not "
            f"the implicit local gateway: {non_local!r}. A PRIVATE_ISOLATED route table's "
            f"complete contents are the VPC-local route(s) and nothing else"
        )
        local_cidrs = sorted(r.get("DestinationCidrBlock") for r in routes
                             if r.get("GatewayId") == "local")
        assert local_cidrs == [vpc_cidr], (
            f"isolated subnet {sid!r} (route table {rtb!r}) has local routes for "
            f"{local_cidrs!r}, expected exactly the VPC CIDR [{vpc_cidr!r}]; without it "
            f"the subnet cannot even reach the rest of its own VPC, and 'no egress' would be "
            f"'no connectivity', a different and wrong outcome"
        )

    # ---- 9. the whole-VPC default-route census --------------------------------------------
    # Derived, not pinned: exactly one default route per PUBLIC subnet and none at all
    # for the isolated ones, so the total equals the public subnet count.
    all_default = [(t["RouteTableId"], r) for t in tables for r in t["Routes"]
                   if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert len(all_default) == len(out_public), (
        f"the VPC's {len(tables)} route tables carry {len(all_default)} routes for 0.0.0.0/0 "
        f"in total ({[(rtb, r.get('GatewayId') or r.get('NatGatewayId')) for rtb, r in all_default]!r}); "
        f"expected exactly {len(out_public)} - one per public subnet and none for the "
        f"{len(out_isolated)} isolated subnets"
    )
    assert {r.get("GatewayId") for _, r in all_default} == {igw_id}, (
        f"the VPC's 0.0.0.0/0 routes target "
        f"{ {r.get('GatewayId') or r.get('NatGatewayId') for _, r in all_default} !r}; with "
        f"nat_gateways=0 the internet gateway {igw_id!r} must be the only default-route target "
        f"anywhere in the VPC"
    )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the on-disk CDK app to a temp workdir so cdk.out / cdk.context.json / out.json are
    never written next to the check."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkiso-"))
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
    defect, not a case to paper over. That matters more here than anywhere - an isolated subnet
    that fell back to the VPC main table would inherit whatever routes that table has, and reading
    the main table instead would report an absence that is not the subnet's own."""
    hits = [t for t in tables
            if any(a.get("SubnetId") == subnet_id for a in t.get("Associations", []))]
    assert len(hits) == 1, (
        f"subnet {subnet_id!r} in {vpc_id!r} has {len(hits)} explicitly associated route tables "
        f"({[t['RouteTableId'] for t in hits]!r}); CDK associates exactly one per subnet, and an "
        f"unassociated subnet silently inherits the VPC main table instead"
    )
    return hits[0]


def _default_route(tables: list[dict[str, Any]], subnet_id: str, vpc_id: str) -> dict[str, Any]:
    """The 0.0.0.0/0 route of the table associated with subnet_id. Used only on the PUBLIC subnets,
    where exactly one is required; the isolated subnets are read through _table_for so their
    ABSENCE of a default route is asserted rather than raised here."""
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
    'live NAT gateways' rather than 'NAT gateway records'. In this file the expected answer is the
    empty list, and the filter is what stops a stale record from a previous run in the same account
    from reading as a NAT gateway this stack created."""
    found: list[dict[str, Any]] = []
    for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filter=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        found.extend(n for n in page["NatGateways"]
                     if n["State"] not in ("deleted", "deleting", "failed"))
    return found


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


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 360.0) -> None:
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
        raise AssertionError("; ".join(errors))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
