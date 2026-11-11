"""cdk-destroy-removes-every-resource-the-stack-created."""
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

CHECK = "cdk-destroy-removes-every-resource-the-stack-created"
GROUP = "deploy-cdk-l2-vpc"
SERVICES = ["cloudformation", "ec2"]

# The three timeouts sum below the check's wall-clock budget, so a cut-off never races cleanup
# against a still-running destroy.
_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0

_APP = Path(__file__).parent / "deployments" / "cdk-vpc-l2-defaults"

_NOT_FOUND_CODES = {
    "AWS::EC2::VPC": "InvalidVpcID.NotFound",
    "AWS::EC2::Subnet": "InvalidSubnetID.NotFound",
    "AWS::EC2::RouteTable": "InvalidRouteTableID.NotFound",
    "AWS::EC2::InternetGateway": "InvalidInternetGatewayID.NotFound",
    "AWS::EC2::EIP": "InvalidAddress.NotFound",
}
# No standalone Describe operation: proven gone through their parents. The check asserts every
# deployed type is probeable, parent-covered or a NAT gateway.
_PARENT_COVERED = {
    "AWS::EC2::Route",
    "AWS::EC2::SubnetRouteTableAssociation",
    "AWS::EC2::VPCGatewayAttachment",
}
_NAT_TYPE = "AWS::EC2::NatGateway"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk destroy` removes every resource its stack created: each is readable before and fails
    with its type's not-found code after, NAT gateways reach a deleted state, and writes against
    the dead VPC and subnet ids are refused.
    """
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys and destroys is missing from disk: expected app.py and "
        f"cdk.json under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkdes-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    work = _stage(ctx, _APP)

    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, (
        f"this region reports {len(azs)} available AZs ({azs!r}); the app's max_azs=2 needs two for "
        f"the estate under test to have its intended shape"
    )

    leaked: list[str] = []
    # The bootstrap staging bucket is retained by its template and `cdk destroy` leaves it and the
    # toolkit stack in place.
    ctx.on_cleanup(lambda: _final_sweep(ctx, staging, toolkit, qualifier, stack))

    _bootstrap(ctx, qualifier, toolkit)
    # Failure-path net only: the asserted teardown is `cdk destroy` in the body below. Registered
    # before the deploy so a part-built stack is deleted before the toolkit stack.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    vpc_id = json.loads((work / "out.json").read_text())[stack]["VpcId"]

    deployed = _stack_resources(cfn, stack)
    assert deployed, f"ListStackResources returned nothing for the deployed stack {stack!r}"
    template = json.loads(
        (work / "cdk.out" / f"{stack}.template.json").read_text())["Resources"]
    want_types = _type_counts(r["Type"] for r in template.values())
    got_types = _type_counts(r["ResourceType"] for r in deployed)
    assert got_types == want_types, (
        f"the deployed stack's resource type counts {got_types!r} differ from the synthesized "
        f"template's {want_types!r}; CloudFormation must have created exactly what CDK "
        f"declared, no more and no less"
    )

    # An unclassified type fails here rather than going unprobed.
    unclassified = sorted(
        set(got_types) - set(_NOT_FOUND_CODES) - _PARENT_COVERED - {_NAT_TYPE})
    assert unclassified == [], (
        f"the deployed stack contains resource types {unclassified!r} that this check has no "
        f"probe for and has not declared parent-covered; it cannot prove they were destroyed, "
        f"so the check must be extended rather than passing"
    )

    # Positive control: without it, "gone" cannot be told from "never created".
    probeable = [r for r in deployed if r["ResourceType"] in _NOT_FOUND_CODES]
    assert probeable, (
        f"none of the {len(deployed)} deployed resources is directly probeable; the check "
        f"cannot prove anything about the destroy"
    )
    for res in probeable:
        _probe(ec2, res)  # raises with a message if it is not readable right now

    nats = [r["PhysicalResourceId"] for r in deployed if r["ResourceType"] == _NAT_TYPE]
    live_before = {n["NatGatewayId"]: n["State"] for n in _nats_in_vpc(ec2, vpc_id)}
    assert sorted(live_before) == sorted(nats), (
        f"before the destroy, DescribeNatGateways reports live gateways {sorted(live_before)!r} "
        f"in {vpc_id!r} but the stack owns {sorted(nats)!r}; the two must agree"
    )
    assert set(live_before.values()) == {"available"}, (
        f"before the destroy the stack's NAT gateways are in states {live_before!r}; all must "
        f"be 'available' for their deletion to be the thing under test"
    )

    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"after `cdk destroy --force`, DescribeStacks on {stack!r} raised {final!r}; expected "
        f"the name not to resolve"
    )

    for res in probeable:
        want = _NOT_FOUND_CODES[res["ResourceType"]]
        got = _error_code(lambda r=res: _probe(ec2, r))
        if got != want:
            leaked.append(
                f"{res['ResourceType']} {res['PhysicalResourceId']} "
                f"(logical {res['LogicalResourceId']}): read failed with {got!r}, expected "
                f"{want!r}")

    # A deleted NAT gateway stays visible in State "deleted" for about an hour.
    after = _nat_states_once_settled(ec2, nats)
    for nat in nats:
        state = after.get(nat)
        if state != "deleted":
            leaked.append(
                f"{_NAT_TYPE} {nat}: State is {state!r} after the destroy, expected 'deleted'")
    still_live = _nats_in_vpc(ec2, vpc_id)
    if still_live:
        leaked.append(
            f"{len(still_live)} NAT gateway(s) are still live after the destroy and are "
            f"billing: { {n['NatGatewayId']: n['State'] for n in still_live} !r}")

    assert leaked == [], (
        "`cdk destroy --force` reported success but the estate it created is still there. "
        "Leaked resources, by id: " + "; ".join(leaked)
    )

    # Writes against a dead id must be refused, not only reads.
    dead_subnets = [r["PhysicalResourceId"] for r in deployed
                    if r["ResourceType"] == "AWS::EC2::Subnet"]
    assert dead_subnets, "the deployed stack declared no subnets to mutate after deletion"
    code, message = _error(lambda: ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.63.240.0/24"))
    want_message = f"The vpc ID '{vpc_id}' does not exist"
    assert (code, message) == ("InvalidVpcID.NotFound", want_message), (
        f"CreateSubnet into the destroyed VPC {vpc_id!r} failed with ({code!r}, {message!r}), "
        f"expected ('InvalidVpcID.NotFound', {want_message!r}) - the id must be unusable for "
        f"writes, not merely unreadable"
    )
    code, message = _error(lambda: ec2.create_tags(
        Resources=[dead_subnets[0]],
        Tags=[{"Key": "sim2real", "Value": CHECK}]))
    want_message = f"The subnet ID '{dead_subnets[0]}' does not exist"
    assert (code, message) == ("InvalidSubnetID.NotFound", want_message), (
        f"CreateTags on the destroyed subnet {dead_subnets[0]!r} failed with "
        f"({code!r}, {message!r}), expected ('InvalidSubnetID.NotFound', {want_message!r})"
    )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and out.json are not written beside it."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkdes-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _error_code(fn) -> str:
    """The AWS error code a call raises; raises AssertionError if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"])
    raise AssertionError("call succeeded but was expected to be refused")


def _error(fn) -> tuple[str, str]:
    """The AWS (error code, message) a call raises; raises AssertionError if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err["Message"])
    raise AssertionError("call succeeded but was expected to be refused")


def _type_counts(types) -> dict[str, int]:
    counts: dict[str, int] = {}
    for t in types:
        counts[t] = counts.get(t, 0) + 1
    return counts


def _stack_resources(cfn, stack: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack):
        for r in page["StackResourceSummaries"]:
            # Hard-subscripted: a summary with no PhysicalResourceId must fail loudly.
            found.append({
                "LogicalResourceId": r["LogicalResourceId"],
                "ResourceType": r["ResourceType"],
                "PhysicalResourceId": r["PhysicalResourceId"],
            })
    return found


def _nat_states_once_settled(ec2, nats: list[str], *, deadline_s: float = 120.0) -> dict[str, str]:
    """NAT gateway states by id, polled while any is still 'deleting' (bounded)."""
    deadline = time.monotonic() + deadline_s
    while True:
        states = {n["NatGatewayId"]: n["State"]
                  for page in ec2.get_paginator("describe_nat_gateways").paginate(
                      NatGatewayIds=nats)
                  for n in page["NatGateways"]}
        if "deleting" not in states.values() or time.monotonic() > deadline:
            return states
        time.sleep(5.0)


def _probe(ec2, res: dict[str, Any]) -> None:
    """Read one stack resource through its own Describe operation.

    Raises ClientError when it is gone, and AssertionError on an empty result set.
    """
    pid, rtype = res["PhysicalResourceId"], res["ResourceType"]
    if rtype == "AWS::EC2::VPC":
        got = ec2.describe_vpcs(VpcIds=[pid])["Vpcs"]
    elif rtype == "AWS::EC2::Subnet":
        got = ec2.describe_subnets(SubnetIds=[pid])["Subnets"]
    elif rtype == "AWS::EC2::RouteTable":
        got = ec2.describe_route_tables(RouteTableIds=[pid])["RouteTables"]
    elif rtype == "AWS::EC2::InternetGateway":
        got = ec2.describe_internet_gateways(InternetGatewayIds=[pid])["InternetGateways"]
    elif rtype == "AWS::EC2::EIP":
        # AWS::EC2::EIP's PhysicalResourceId is the public IP address.
        got = ec2.describe_addresses(PublicIps=[pid])["Addresses"]
    else:
        raise AssertionError(f"no probe defined for resource type {rtype!r} (physical id {pid!r})")
    assert got, (
        f"{rtype} {pid!r} returned an empty result set without raising; a Describe by explicit id "
        f"must either return the resource or raise its not-found error"
    )


def _nats_in_vpc(ec2, vpc_id: str) -> list[dict[str, Any]]:
    """Every NAT gateway in the VPC that is not already torn down.

    Deleted gateways stay visible for about an hour, so they are filtered out.
    """
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
    # has aws-cdk-lib importable; cdk.json keeps the plain form so the app synthesizes standalone.
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


def _final_sweep(ctx, staging: str, toolkit: str, qualifier: str, stack: str) -> None:
    """Delete the bootstrap staging bucket and toolkit stack once the app stack is gone; raise
    naming anything left behind. The app stack deletes as the toolkit's exec role."""
    try:
        status = ctx.client("cloudformation").describe_stacks(
            StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
            raise
        status = "DELETE_COMPLETE"
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"app stack {stack} is {status!r}: toolkit stack {toolkit} and "
                             f"staging bucket kept so the app stack can still be deleted")
    errors: list[str] = []
    for label, fn in (
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected and raised below, every step still runs
            errors.append(f"{label}: {exc!r}")
    iam = ctx.client("iam")
    roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        errors.append(f"bootstrap roles {roles!r}")
    if errors:
        raise AssertionError(f"teardown left resources behind: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
