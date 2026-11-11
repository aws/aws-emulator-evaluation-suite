"""cdk-diff-sees-a-template-change-and-is-blind-to-resource-drift."""
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

CHECK = "cdk-diff-sees-a-template-change-and-is-blind-to-resource-drift"
GROUP = "deploy-cdk-l2-vpc"
SERVICES = ["cloudformation", "ec2"]

# `cdk diff` compares the locally synthesized template with the template CloudFormation holds, so a
# real-resource mutation is invisible to it; drift detection is the API that sees one.
# The app has no NAT gateway: the app needs no egress.
_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 480.0
_DIFF_TIMEOUT_S = 120.0  # `cdk diff --no-change-set` is local plus one GetTemplate call
_DRIFT_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 480.0

_APP = Path(__file__).parent / "deployments" / "cdk-vpc-diff-subject"
_NO_DIFF_MARKER = "Number of stacks with differences: 0"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`cdk diff --fail` stays clean after an out-of-band MapPublicIpOnLaunch flip that drift
    detection reports MODIFIED (IN_SYNC after restore), and fails naming a changed local tag value
    without mutating the deployed template.
    """
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys is missing from disk: expected app.py and cdk.json under "
        f"{_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkdiff-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    work = _stage(ctx, _APP)

    marker_a = ctx.unique_name("marker-a-")
    marker_b = ctx.unique_name("marker-b-")
    state: dict[str, Any] = {"vpc": None}

    azs = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(azs) >= 2, (
        f"this region reports {len(azs)} available AZs ({azs!r}); the app's max_azs=2 needs two"
    )

    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    _bootstrap(ctx, qualifier, toolkit)

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, marker_a, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    vpc_id = outputs["VpcId"]
    state["vpc"] = vpc_id
    public = sorted(outputs["PublicSubnetIds"].split(","))
    assert len(public) == 2, (
        f"the stack reported public subnets {public!r}; the app declares max_azs=2 with a single "
        f"PUBLIC subnet configuration, so exactly two are expected"
    )
    subject = public[0]

    # The template value arm 2 will compare drift against. Read from CloudFormation, not from
    # the local file: the deployed template is what drift detection uses.
    deployed_tmpl = _deployed_template(cfn, stack)
    declared = _declared_map_public_ip(deployed_tmpl)
    assert declared is True, (
        f"the deployed template declares MapPublicIpOnLaunch {declared!r} for its public "
        f"subnets, expected True; without a declared true value there is nothing for drift "
        f"detection to compare the mutation against"
    )

    # ---- ARM 1: a real-resource mutation cdk diff must NOT see ------------------------------
    ec2.modify_subnet_attribute(SubnetId=subject,
                                MapPublicIpOnLaunch={"Value": False})
    ctx.on_cleanup(lambda: _restore_map_public_ip_or_gone(ec2, subject))
    # Prove the mutation LANDED before asserting anything is blind to it, through a different
    # operation than the one that made it. Bounded retry: ModifySubnetAttribute's effect on
    # DescribeSubnets is read-after-write in principle but not documented as such.
    _await_map_public_ip(ec2, subject, False)

    # --fail makes the exit code meaningful; --no-change-set keeps it a template-only diff.
    rc, out = _cdk(ctx, work, ["diff", "--fail", "--no-change-set"], qualifier, stack, marker_a,
                   timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 0, (
        f"`cdk diff --fail` exited {rc} after MapPublicIpOnLaunch was flipped to False on "
        f"{subject!r} out of band; expected 0. `cdk diff` compares the local template with the "
        f"DEPLOYED TEMPLATE and neither changed, so a non-zero exit means the target is diffing "
        f"resource state, which real AWS's CDK CLI does not do. Output tail: {out[-600:]!r}"
    )
    assert _NO_DIFF_MARKER in out, (
        f"`cdk diff` reported differences after an out-of-band resource mutation; it must "
        f"report {_NO_DIFF_MARKER!r}. Output tail: {out[-600:]!r}"
    )

    # ---- ARM 2: the API that DOES see it, plus a restore leg --------------------------------
    drift = _detect_drift(cfn, stack)
    assert drift["StackDriftStatus"] == "DRIFTED", (
        f"after MapPublicIpOnLaunch was flipped on {subject!r}, DetectStackDrift reports "
        f"StackDriftStatus {drift['StackDriftStatus']!r}, expected 'DRIFTED'"
    )
    drifts = _resource_drifts(cfn, stack)
    mine = [d for d in drifts if d["PhysicalResourceId"] == subject]
    assert len(mine) == 1, (
        f"drift detection returned {len(mine)} entries for the mutated subnet {subject!r}, "
        f"expected exactly 1; entries seen: "
        f"{ {d['PhysicalResourceId']: d['StackResourceDriftStatus'] for d in drifts} !r}"
    )
    assert mine[0]["StackResourceDriftStatus"] == "MODIFIED", (
        f"the mutated subnet {subject!r} has StackResourceDriftStatus "
        f"{mine[0]['StackResourceDriftStatus']!r}, expected 'MODIFIED'"
    )
    props = [p for p in mine[0]["PropertyDifferences"]
             if p["PropertyPath"] == "/MapPublicIpOnLaunch"]
    assert len(props) == 1, (
        f"drift on {subject!r} reported property paths "
        f"{[p['PropertyPath'] for p in mine[0]['PropertyDifferences']]!r}; expected exactly one "
        f"at '/MapPublicIpOnLaunch' - a bare MODIFIED status without the property path does not "
        f"tell an operator what changed"
    )
    got_values = (props[0]["ExpectedValue"], props[0]["ActualValue"])
    assert got_values == ("true", "false"), (
        f"drift on {subject!r} reports (ExpectedValue, ActualValue) {got_values!r}; the template "
        f"declared true and the mutation set false, so ('true', 'false') is required"
    )
    assert props[0]["DifferenceType"] == "NOT_EQUAL", (
        f"drift on {subject!r} reports DifferenceType {props[0]['DifferenceType']!r}, expected "
        f"'NOT_EQUAL' for a property present in both the template and the resource"
    )

    # Restore, and demand the drift verdict comes back clean.
    ec2.modify_subnet_attribute(SubnetId=subject, MapPublicIpOnLaunch={"Value": True})
    _await_map_public_ip(ec2, subject, True)
    _detect_drift(cfn, stack)
    restored = [d for d in _resource_drifts(cfn, stack)
                if d["PhysicalResourceId"] == subject]
    assert len(restored) == 1 and restored[0]["StackResourceDriftStatus"] == "IN_SYNC", (
        f"after MapPublicIpOnLaunch was restored to True, drift on {subject!r} reports "
        f"{[d['StackResourceDriftStatus'] for d in restored]!r}, expected exactly ['IN_SYNC'] - "
        f"a target reporting MODIFIED here is reporting drift unconditionally rather than "
        f"tracking the resource"
    )

    # ---- ARM 3: a LOCAL template change cdk diff MUST see; arm 1's clean exit on the original
    # marker shows this exit tracks the template value rather than always failing. ------------
    rc, out = _cdk(ctx, work, ["diff", "--fail", "--no-change-set"], qualifier, stack, marker_b,
                   timeout_s=_DIFF_TIMEOUT_S, expect_rc=None)
    assert rc == 1, (
        f"`cdk diff --fail` exited {rc} after the app's Sim2realDiffMarker tag changed from "
        f"{marker_a!r} to {marker_b!r}; a changed local template must exit 1 under --fail. "
        f"Output tail: {out[-600:]!r}"
    )
    assert marker_b in out, (
        f"`cdk diff` reported a difference but its output does not name the new tag value "
        f"{marker_b!r}, so an operator cannot see what changed. Output tail: {out[-800:]!r}"
    )
    # Effect-absent: a diff is a read. It must not have MUTATED the deployed stack.
    assert _deployed_template(cfn, stack) == deployed_tmpl, (
        "`cdk diff` changed the template CloudFormation holds for the deployed stack; a diff is "
        "a read and must not mutate the stack"
    )


def _stage(ctx, app_dir: Path) -> Path:
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkdiff-"))
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


def _restore_map_public_ip_or_gone(ec2, subnet_id: str) -> None:
    """Undo the out-of-band flip; a no-op once the stack teardown has already deleted the subnet."""
    try:
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _deployed_template(cfn, stack: str) -> dict[str, Any]:
    body = cfn.get_template(StackName=stack)["TemplateBody"]
    return json.loads(body) if isinstance(body, str) else json.loads(json.dumps(body))


def _declared_map_public_ip(template: dict[str, Any]) -> Any:
    """The MapPublicIpOnLaunch the deployed template declares for its subnets, asserting all subnets
    agree - the check mutates one and needs a single unambiguous expected value."""
    subnets = [v for v in template["Resources"].values() if v["Type"] == "AWS::EC2::Subnet"]
    assert subnets, "the deployed template declares no AWS::EC2::Subnet resources"
    values = {json.dumps(s["Properties"].get("MapPublicIpOnLaunch")) for s in subnets}
    assert len(values) == 1, (
        f"the deployed template's subnets declare differing MapPublicIpOnLaunch values {values!r}; "
        f"this check needs one unambiguous declared value to compare drift against"
    )
    return json.loads(next(iter(values)))


def _await_map_public_ip(ec2, subnet_id: str, want: bool, timeout_s: float = 120.0) -> None:
    """Bounded retry until DescribeSubnets reports the value ModifySubnetAttribute just set.

    Read-after-write on a subnet attribute is not documented as guaranteed. Raises on timeout.
    """
    deadline = time.monotonic() + timeout_s
    seen: Any = "never read"
    while True:
        subnets = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"]
        assert len(subnets) == 1, (
            f"DescribeSubnets for {subnet_id!r} returned {len(subnets)} subnets, expected 1"
        )
        seen = subnets[0]["MapPublicIpOnLaunch"]
        if seen is want:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"after {timeout_s}s DescribeSubnets still reports MapPublicIpOnLaunch {seen!r} for "
                f"{subnet_id!r}; ModifySubnetAttribute was called with {want!r}"
            )
        time.sleep(2.0)


def _detect_drift(cfn, stack: str) -> dict[str, Any]:
    """Start a drift detection and poll it out of DETECTION_IN_PROGRESS, then require
    DETECTION_COMPLETE, so a failed detection cannot be read as 'no drift'."""
    did = cfn.detect_stack_drift(StackName=stack)["StackDriftDetectionId"]
    deadline = time.monotonic() + _DRIFT_TIMEOUT_S
    while True:
        status = cfn.describe_stack_drift_detection_status(StackDriftDetectionId=did)
        if status["DetectionStatus"] != "DETECTION_IN_PROGRESS" or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert status["DetectionStatus"] == "DETECTION_COMPLETE", (
        f"drift detection {did!r} on {stack!r} is {status['DetectionStatus']!r} after "
        f"{_DRIFT_TIMEOUT_S}s, expected DETECTION_COMPLETE; reason "
        f"{status.get('DetectionStatusReason')!r}"
    )
    return status


def _resource_drifts(cfn, stack: str) -> list[dict[str, Any]]:
    """Per-resource drift for a completed detection. PropertyDifferences defaults to [] only
    because callers filter it and then assert an exact length."""
    found: list[dict[str, Any]] = []
    # botocore declares no paginator for describe_stack_resource_drifts, though the API takes and
    # returns NextToken; a first-page-only read would silently truncate the drift set this asserts on.
    pages = []
    token = None
    while True:
        kwargs = {"StackName": stack}
        if token:
            kwargs["NextToken"] = token
        page = cfn.describe_stack_resource_drifts(**kwargs)
        pages.append(page)
        token = page.get("NextToken")
        if not token:
            break
    for page in pages:
        for d in page["StackResourceDrifts"]:
            found.append({
                "LogicalResourceId": d["LogicalResourceId"],
                "PhysicalResourceId": d.get("PhysicalResourceId", ""),
                "StackResourceDriftStatus": d["StackResourceDriftStatus"],
                "PropertyDifferences": d.get("PropertyDifferences", []),
            })
    assert found, (
        f"DescribeStackResourceDrifts returned no entries for {stack!r} after detection "
        f"completed"
    )
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


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, marker: str, *,
         timeout_s: float, expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI against the staged app. `marker` is the app's DIFF_MARKER - the ONE value the
    check varies to produce a local template change, and the reason no branch is needed in app.py."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    env["DIFF_MARKER"] = marker
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


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 420.0) -> None:
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
        for label, name in (("app stack", stack), ("toolkit stack", toolkit)):
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
        roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
                 for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
        if roles:
            remaining.append(f"bootstrap roles {roles!r}")
        if not remaining:
            break
        time.sleep(10.0)
    else:
        errors.append(f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")

    # Confirm the VPC this check created is gone.
    if state.get("vpc") and not errors:
        code = _error_code(lambda: ctx.client("ec2").describe_vpcs(VpcIds=[state["vpc"]]))
        if code != "InvalidVpcID.NotFound":
            errors.append(
                f"after teardown DescribeVpcs({state['vpc']!r}) failed with {code!r}, "
                f"expected 'InvalidVpcID.NotFound'")
    assert not errors, "teardown left the estate dirty: " + "; ".join(errors)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
