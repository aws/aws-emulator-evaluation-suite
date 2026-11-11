"""cdk-vpc-context-lookup-denied-lookup-role-fails-synth."""
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
from fidelity_tests_runner import require_tools

CHECK = "cdk-vpc-context-lookup-denied-lookup-role-fails-synth"
GROUP = "deploy-cdk-context-provider"
SERVICES = ["cloudformation", "ec2", "iam", "ssm"]

# Bounds for a bootstrap, a VPC build, three synths and a verified inline teardown.
_BOOTSTRAP_TIMEOUT_S = 900.0
_SYNTH_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0
_IAM_PROPAGATION_BUDGET_S = 120.0

# The dummy CDK substitutes when a context lookup does not resolve: a denied lookup role does not
# stop `cdk synth` from writing a template; it writes one carrying this literal and exits non-zero.
_CDK_DUMMY_VPC_ID = "vpc-12345"

_APP_PY = '''\
import os
import aws_cdk as cdk
from aws_cdk import aws_ec2 as ec2, aws_ssm as ssm


class LookupStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        vpc = ec2.Vpc.from_lookup(self, "V", tags={"Name": os.environ["VPC_NAME"]})
        marker = ssm.StringParameter.value_from_lookup(self, os.environ["PARAM_NAME"])
        sg = ec2.SecurityGroup(self, "SG", vpc=vpc, allow_all_outbound=False,
                               description="sim2real cdk lookup probe")
        cdk.CfnOutput(self, "VpcId", value=vpc.vpc_id)
        cdk.CfnOutput(self, "Marker", value=marker)
        cdk.CfnOutput(self, "SgId", value=sg.security_group_id)


app = cdk.App()
LookupStack(app, os.environ["STACK_NAME"],
            synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
            env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                                region=os.environ["CDK_DEFAULT_REGION"]))
app.synth()
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CDK VPC lookup at synth partitions real subnets into Public/Isolated by their route tables;
    with ec2:DescribeVpcs denied to the lookup role, synth exits non-zero and writes the dummy
    vpc-12345 instead of a real id, and removing the deny restores the original context.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/context.html
    """
    require_tools("cdk")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdklk-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    vpc_name = ctx.unique_name("sim2real-cdklookup-")
    param_name = "/sim2real/cdklookup/" + ctx.unique_name("")
    marker = ctx.unique_name("marker-")
    lookup_role = f"cdk-{qualifier}-lookup-role-{acct}-{ctx.region}"

    rtags = [{"Key": "Name", "Value": vpc_name}, {"Key": "sim2real", "Value": CHECK}]
    estate: dict[str, Any] = {"subnets": [], "route_tables": [], "vpc": None, "igw": None}

    work = Path(tempfile.mkdtemp(prefix="sim2real-cdklk-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    (work / "app.py").write_text(_APP_PY)

    try:
        # --- the real estate the lookup must discover, built with boto3 so the expected values are
        # --- known independently of anything CDK reports.
        vpc_id = ec2.create_vpc(
            CidrBlock="10.42.0.0/16",
            TagSpecifications=[{"ResourceType": "vpc", "Tags": rtags}],
        )["Vpc"]["VpcId"]
        estate["vpc"] = vpc_id
        ctx.on_cleanup(lambda: _delete_vpc_estate(ctx, estate))

        igw_id = ec2.create_internet_gateway(
            TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": rtags}],
        )["InternetGateway"]["InternetGatewayId"]
        estate["igw"] = igw_id
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

        # Derive the AZs rather than hardcoding: AZ names are per-account aliases and an
        # unavailable zone would fail the subnet create.
        usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
        assert len(usable) >= 2, (
            f"this region reports only {usable!r} available AZs; the check needs two"
        )
        azs = usable[:2]

        public, isolated = [], []
        for i, az in enumerate(azs):
            public.append(ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": rtags}],
            )["Subnet"]["SubnetId"])
            isolated.append(ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.42.{i + 10}.0/24", AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": rtags}],
            )["Subnet"]["SubnetId"])
        estate["subnets"] = public + isolated

        public_rt = ec2.create_route_table(
            VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": rtags}],
        )["RouteTable"]["RouteTableId"]
        estate["route_tables"].append(public_rt)
        ec2.create_route(RouteTableId=public_rt, DestinationCidrBlock="0.0.0.0/0",
                         GatewayId=igw_id)
        for s in public:
            ec2.associate_route_table(RouteTableId=public_rt, SubnetId=s)

        isolated_rt = ec2.create_route_table(
            VpcId=vpc_id, TagSpecifications=[{"ResourceType": "route-table", "Tags": rtags}],
        )["RouteTable"]["RouteTableId"]
        estate["route_tables"].append(isolated_rt)
        for s in isolated:
            ec2.associate_route_table(RouteTableId=isolated_rt, SubnetId=s)

        ssm.put_parameter(Name=param_name, Value=marker, Type="String",
                          Tags=[{"Key": "sim2real", "Value": CHECK}])
        ctx.on_cleanup(lambda: _swallow_missing(lambda: ssm.delete_parameter(Name=param_name)))

        _bootstrap(ctx, qualifier, toolkit)
        ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, toolkit))
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, staging))

        env = _synth_env(ctx, qualifier, stack, vpc_name, param_name)
        _synth(work, env, expect_rc=0, timeout_s=_SYNTH_TIMEOUT_S)
        good_context = json.loads((work / "cdk.context.json").read_text())

        # 1. exactly one vpc-provider entry, and it is the VPC this check created.
        vpc_keys = [k for k in good_context if k.startswith("vpc-provider:")]
        assert len(vpc_keys) == 1, (
            f"cdk.context.json has vpc-provider keys {vpc_keys!r}, expected exactly one"
        )
        found = good_context[vpc_keys[0]]
        assert found["vpcId"] == vpc_id, (
            f"the lookup resolved vpcId {found['vpcId']!r}, expected {vpc_id!r}"
        )
        assert found["vpcCidrBlock"] == "10.42.0.0/16", (
            f"the lookup resolved vpcCidrBlock {found['vpcCidrBlock']!r}, expected '10.42.0.0/16'"
        )
        assert found["ownerAccountId"] == acct, (
            f"the lookup resolved ownerAccountId {found['ownerAccountId']!r}, expected {acct!r}"
        )

        # 2./3. the partition, by route table. Public is the group whose route table has the IGW
        #       route; Isolated is the group with no egress route at all. No NAT gateway is built,
        #       so CDK's Private subnet class is not covered.
        groups = {g["type"]: g for g in found["subnetGroups"]}
        assert sorted(groups) == ["Isolated", "Public"], (
            f"the lookup partitioned the VPC into subnet-group types {sorted(groups)!r}; two "
            f"route tables — one with a 0.0.0.0/0 -> {igw_id} route, one with none — must yield "
            f"exactly ['Isolated', 'Public']"
        )
        assert {s["subnetId"] for s in groups["Public"]["subnets"]} == set(public), (
            f"Public group is {[s['subnetId'] for s in groups['Public']['subnets']]!r}, expected "
            f"the two subnets associated with the IGW route table: {public!r}"
        )
        assert {s["subnetId"] for s in groups["Isolated"]["subnets"]} == set(isolated), (
            f"Isolated group is {[s['subnetId'] for s in groups['Isolated']['subnets']]!r}, "
            f"expected the two subnets with no egress route: {isolated!r}"
        )

        # 4. the route-table ids CDK recorded are the real associations, per subnet.
        for gtype, expected_rt in (("Public", public_rt), ("Isolated", isolated_rt)):
            got = {s["routeTableId"] for s in groups[gtype]["subnets"]}
            assert got == {expected_rt}, (
                f"{gtype} subnets report routeTableId {got!r}, expected {{{expected_rt!r}}}"
            )

        # 5. the AZs, exact and per subnet.
        for gtype, members in (("Public", public), ("Isolated", isolated)):
            by_subnet = {s["subnetId"]: s["availabilityZone"] for s in groups[gtype]["subnets"]}
            assert sorted(by_subnet.values()) == azs, (
                f"{gtype} subnets resolved to AZs {sorted(by_subnet.values())!r}, expected {azs!r}"
            )
            assert by_subnet[members[0]] == azs[0] and by_subnet[members[1]] == azs[1], (
                f"{gtype} subnet-to-AZ mapping was {by_subnet!r}, expected {members[0]!r} in "
                f"{azs[0]!r} and {members[1]!r} in {azs[1]!r}"
            )

        # 6. the SSM context entry carries the value this check wrote.
        ssm_keys = [k for k in good_context if k.startswith("ssm:")]
        assert len(ssm_keys) == 1, f"expected one ssm: context entry, got {ssm_keys!r}"
        assert good_context[ssm_keys[0]] == marker, (
            f"the ssm lookup resolved {good_context[ssm_keys[0]]!r}, expected {marker!r}"
        )

        # 7. the lookup fed the template: a looked-up VPC id is a LITERAL, not a Ref.
        good_template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
        sg_vpc = _sg_vpc_id(good_template)
        assert sg_vpc == vpc_id, (
            f"the synthesized SecurityGroup's VpcId was {sg_vpc!r}, expected the literal real id "
            f"{vpc_id!r}"
        )
        assert good_template["Outputs"]["Marker"]["Value"] == marker, (
            f"the template's Marker output was {good_template['Outputs']['Marker']['Value']!r}, "
            f"expected the resolved parameter value {marker!r}"
        )

        # 8. NEGATIVE: deny the LOOKUP ROLE ec2:DescribeVpcs. Break exactly one thing.
        iam.put_role_policy(
            RoleName=lookup_role, PolicyName="Sim2realDenyDescribeVpcs",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                {"Effect": "Deny", "Action": "ec2:DescribeVpcs", "Resource": "*"}]}),
        )
        ctx.on_cleanup(lambda: _drop_deny(iam, lookup_role))
        _clear_assembly(work)
        # No API reports that an identity policy has become effective, so the only correct wait is
        # to poll for the DENY taking effect on the thing that must observe it — the synth itself.
        rc, out = _poll_for_denied_synth(work, env)
        assert rc != 0, (
            f"`cdk synth` exited 0 while the lookup role was denied ec2:DescribeVpcs; output tail: "
            f"{out[-600:]!r}"
        )
        assert "ec2:DescribeVpcs" in out and lookup_role in out, (
            f"the synth failure named neither ec2:DescribeVpcs nor the lookup role {lookup_role!r}; "
            f"output tail: {out[-800:]!r}"
        )

        # 9. effect-absent, and the reason this check exists: no vpc-provider context was written,
        #    and the template CDK still wrote carries the DUMMY id, not a real one.
        denied_context = json.loads((work / "cdk.context.json").read_text())
        assert [k for k in denied_context if k.startswith("vpc-provider:")] == [], (
            f"a vpc-provider context entry was written despite the denied lookup: "
            f"{sorted(denied_context)!r} — the lookup result must not be fabricated"
        )
        denied_template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
        denied_vpc = _sg_vpc_id(denied_template)
        assert denied_vpc == _CDK_DUMMY_VPC_ID, (
            f"under a denied lookup the synthesized template's VpcId was {denied_vpc!r}; CDK must "
            f"substitute its dummy {_CDK_DUMMY_VPC_ID!r} rather than any real or invented id"
        )
        assert denied_vpc != vpc_id, (
            f"the denied synth still produced the real VPC id {vpc_id!r} — the deny was not honoured"
        )

        # 10. CONTROL: remove the one thing that was broken; the identical values come back.
        _drop_deny(iam, lookup_role)
        _clear_assembly(work)
        _synth(work, env, expect_rc=0, timeout_s=_SYNTH_TIMEOUT_S, retry_on="DescribeVpcs")
        again = json.loads((work / "cdk.context.json").read_text())
        assert again == good_context, (
            f"control: after removing the deny the context resolved to {json.dumps(again)[:400]!r}, "
            f"which differs from the first resolution — the deny arm was not the only difference"
        )
        assert _sg_vpc_id(json.loads(
            (work / "cdk.out" / f"{stack}.template.json").read_text())) == vpc_id, (
            "control: the re-synthesized template does not carry the real VPC id"
        )
    finally:
        # Verified inline teardown: the 60 s cleanup cap cannot cover a VPC teardown plus a stack
        # delete plus a versioned-bucket purge; the registrations above are the failure-path net.
        _teardown(ctx, estate, staging, toolkit, qualifier, param_name, lookup_role)


# ===== helpers =====


def _sg_vpc_id(template: dict[str, Any]) -> str:
    sgs = [v for v in template["Resources"].values() if v["Type"] == "AWS::EC2::SecurityGroup"]
    assert len(sgs) == 1, f"template has {len(sgs)} security groups, expected 1"
    return sgs[0]["Properties"]["VpcId"]


def _synth_env(ctx, qualifier: str, stack: str, vpc_name: str, param_name: str) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["VPC_NAME"] = vpc_name
    env["PARAM_NAME"] = param_name
    return env


def _clear_assembly(work: Path) -> None:
    """Force the next synth to perform the lookup again rather than reading its own cache."""
    (work / "cdk.context.json").unlink(missing_ok=True)
    shutil.rmtree(work / "cdk.out", ignore_errors=True)


def _synth(work: Path, env: dict[str, str], *, expect_rc: int | None, timeout_s: float,
           retry_on: str | None = None) -> tuple[int, str]:
    cmd = ["cdk", "synth", "--ci", "--no-version-reporting", "--app", f"{sys.executable} app.py"]
    deadline = time.monotonic() + timeout_s
    rc, out = -1, ""
    while True:
        r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                           timeout=max(60.0, deadline - time.monotonic()))
        rc, out = r.returncode, r.stdout + r.stderr
        # Bounded retry for the POSITIVE/control arms only: removing an identity policy is
        # eventually consistent. Never applied to the negative arm.
        if rc == 0 or retry_on is None or retry_on not in out or time.monotonic() >= deadline:
            break
        _clear_assembly(work)
        time.sleep(2)
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk synth` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _poll_for_denied_synth(work: Path, env: dict[str, str]) -> tuple[int, str]:
    """Poll until the newly-attached deny is observably in effect, bounded. Returns the first synth
    that failed; if none fails within the budget the last result is returned so the caller's assert
    reports the real observation rather than a timeout."""
    deadline = time.monotonic() + _IAM_PROPAGATION_BUDGET_S
    rc, out = 0, ""
    while True:
        rc, out = _synth(work, env, expect_rc=None, timeout_s=_SYNTH_TIMEOUT_S)
        if rc != 0 or time.monotonic() >= deadline:
            return rc, out
        _clear_assembly(work)
        time.sleep(2)


def _drop_deny(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="Sim2realDenyDescribeVpcs")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    version = subprocess.run(["cdk", "--version"], env=ctx.subprocess_env(),
                             capture_output=True, text=True, timeout=120)
    assert version.returncode == 0, (
        f"the CDK CLI is required and did not run: rc={version.returncode} "
        f"stderr={version.stderr[-300:]!r}"
    )
    r = subprocess.run(
        ["cdk", "bootstrap", f"aws://{acct}/{ctx.region}", "--qualifier", qualifier,
         "--toolkit-stack-name", toolkit,
         # AWS_MANAGED_KEY explicitly: an empty value fires the template's CreateNewKey condition
         # and mints a customer CMK with a 7-day irreversible deletion window.
         "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci"],
        cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if "does not exist" not in str(exc):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" not in str(exc):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        time.sleep(2)
    raise AssertionError(f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s")


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


def _delete_vpc_estate(ctx, estate: dict[str, Any]) -> None:
    """Children before parents: subnets, then route tables, then detach+delete the IGW, then the
    VPC."""
    ec2 = ctx.client("ec2")
    for sid in estate.get("subnets", []):
        _swallow_missing(lambda sid=sid: ec2.delete_subnet(SubnetId=sid))
    for rtb in estate.get("route_tables", []):
        _swallow_missing(lambda rtb=rtb: ec2.delete_route_table(RouteTableId=rtb))
    if estate.get("igw") and estate.get("vpc"):
        _swallow_missing(lambda: ec2.detach_internet_gateway(
            InternetGatewayId=estate["igw"], VpcId=estate["vpc"]))
    if estate.get("igw"):
        _swallow_missing(lambda: ec2.delete_internet_gateway(
            InternetGatewayId=estate["igw"]))
    if estate.get("vpc"):
        _swallow_missing(lambda: ec2.delete_vpc(VpcId=estate["vpc"]))


def _swallow_missing(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise


def _teardown(ctx, estate: dict[str, Any], staging: str, toolkit: str, qualifier: str,
              param_name: str, lookup_role: str) -> None:
    """Delete, then poll until the API says it is gone, and raise on what remains. The staging
    bucket is deleted explicitly: the bootstrap template retains it on a toolkit delete."""
    found = sys.exc_info()[1]
    prefix = f"{found!r}; " if found else ""
    errors: list[str] = []
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    for label, fn in (
        ("lookup-role deny", lambda: _drop_deny(iam, lookup_role)),
        (f"ssm parameter {param_name}", lambda: _swallow_missing(
            lambda: ssm.delete_parameter(Name=param_name))),
        ("vpc estate", lambda: _delete_vpc_estate(ctx, estate)),
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — collected, raised below
            errors.append(f"{label}: {exc!r}")

    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining: list[str] = ["teardown verification never ran"]
    while time.monotonic() < deadline:
        remaining = []
        try:
            st = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {st}")
        except ClientError as exc:
            if "does not exist" not in str(exc):
                raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        try:
            s3.head_bucket(Bucket=staging)
            remaining.append("staging bucket still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket", "NotFound"):
                raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        try:
            ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append("bootstrap version parameter still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        try:
            ssm.get_parameter(Name=param_name)
            remaining.append(f"parameter {param_name} still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        if estate.get("vpc"):
            try:
                ec2.describe_vpcs(VpcIds=[estate["vpc"]])
                remaining.append(f"vpc {estate['vpc']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                    raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
                 for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
        if roles:
            remaining.append(f"bootstrap roles {roles!r}")
        if not remaining:
            break
        time.sleep(2)
    else:
        errors.append(f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")
    if errors:
        raise AssertionError(f"{prefix}teardown did not complete: " + "; ".join(errors))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
