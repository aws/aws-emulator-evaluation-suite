"""cdk-vpc-lookup-context-cache-outlives-a-denied-lookup-role."""
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

CHECK = "cdk-vpc-lookup-context-cache-outlives-a-denied-lookup-role"
GROUP = "deploy-cdk-context-provider"
SERVICES = ["cloudformation", "ec2", "iam"]

# Bounds for a bootstrap, four synths and a verified teardown.
_BOOTSTRAP_TIMEOUT_S = 900.0
_SYNTH_TIMEOUT_S = 300.0
# One deadline for every teardown step and its verification, inside the suite's cleanup budget.
_TEARDOWN_DEADLINE_S = 900.0
_PERMISSION_PROPAGATION_BUDGET_S = 300.0
_PERMISSION_POLL_INTERVAL_S = 10.0

_APP = Path(__file__).parent / "deployments" / "cdk-vpc-lookup-cache"
_DENY_POLICY_NAME = "Sim2realDenyDescribeVpcs"
_DENY_MARKERS = ("is not authorized to perform: ec2:DescribeVpcs",
                 "with an explicit deny in an identity-based policy")


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CDK VPC lookup through the bootstrap lookup role resolves the VPC, its CIDR and its one
    Isolated subnet; with the role denied ec2:DescribeVpcs an uncached lookup is refused with EC2's
    explicit-deny message, and resolves identically once the deny is removed.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/context.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")
    ident = ctx.client("sts").get_caller_identity()
    acct = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check references is missing from disk: expected app.py and cdk.json "
        f"under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdklkc-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    tag_value = ctx.unique_name("cdklkc-")
    lookup_role = f"cdk-{qualifier}-lookup-role-{acct}-{ctx.region}"
    lookup_role_arn = f"arn:{partition}:iam::{acct}:role/{lookup_role}"

    estate: dict[str, Any] = {"vpc": None, "subnet": None}
    # Registered before anything is created; reads `estate` as the body fills it in.
    ctx.on_cleanup(lambda: _teardown(ctx, estate, acct, staging, toolkit, qualifier, lookup_role))
    work = _stage(ctx, _APP)

    az = _usable_az(ec2)

    vpc_id = ec2.create_vpc(
        CidrBlock="10.93.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc",
                            "Tags": [{"Key": "sim2real", "Value": tag_value}]}],
    )["Vpc"]["VpcId"]
    estate["vpc"] = vpc_id

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.93.0.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet",
                            "Tags": [{"Key": "sim2real", "Value": tag_value}]}],
    )["Subnet"]["SubnetId"]
    estate["subnet"] = subnet_id

    _bootstrap(ctx, acct, qualifier, toolkit)

    env = _synth_env(ctx, acct, qualifier, stack, tag_value)

    # 1. GOOD: a fresh synth with no cache present performs the lookup through the lookup role.
    _synth(work, env, expect_rc=0, timeout_s=_SYNTH_TIMEOUT_S)
    good_context = json.loads((work / "cdk.context.json").read_text())
    good_template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())

    vpc_keys = [k for k in good_context if k.startswith("vpc-provider:")]
    assert len(vpc_keys) == 1, (
        f"cdk.context.json holds vpc-provider keys {vpc_keys!r}, expected exactly one"
    )
    found = good_context[vpc_keys[0]]
    assert found["vpcId"] == vpc_id, (
        f"the lookup resolved vpcId {found['vpcId']!r}, expected {vpc_id!r}"
    )
    assert found["vpcCidrBlock"] == "10.93.0.0/16", (
        f"the lookup resolved vpcCidrBlock {found['vpcCidrBlock']!r}, expected '10.93.0.0/16'"
    )
    assert found["ownerAccountId"] == acct, (
        f"the lookup resolved ownerAccountId {found['ownerAccountId']!r}, expected {acct!r}"
    )
    groups = found["subnetGroups"]
    assert len(groups) == 1 and groups[0]["type"] == "Isolated", (
        f"the lookup partitioned the VPC into group types {[g['type'] for g in groups]!r}; "
        f"one subnet with no egress route must yield exactly one Isolated group"
    )
    assert {s["subnetId"] for s in groups[0]["subnets"]} == {subnet_id}, (
        f"the Isolated group holds {[s['subnetId'] for s in groups[0]['subnets']]!r}, "
        f"expected the one subnet this check created: {subnet_id!r}"
    )
    sg_vpc = _sg_vpc_id(good_template)
    assert sg_vpc == vpc_id, (
        f"the synthesized SecurityGroup's VpcId is {sg_vpc!r}, expected the literal real id "
        f"{vpc_id!r}; a Ref or a token means the lookup did not resolve"
    )

    # 2. Deny the LOOKUP ROLE the permission the provider needs, and confirm the deny is in
    #    effect by calling the API as that role, bounded: an identity-policy change is
    #    eventually consistent, and this is where the check's own first use of it happens.
    iam.put_role_policy(
        RoleName=lookup_role, PolicyName=_DENY_POLICY_NAME,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Deny", "Action": "ec2:DescribeVpcs", "Resource": "*"}]}),
    )
    _wait_for_describe_vpcs(ctx, lookup_role_arn, vpc_id, want_denied=True)

    # 3. Setup for the uncached arm: with the cache file untouched the synth answers from
    #    cdk.context.json without calling AWS, so this arm grades the CLI, not the target; it
    #    pins that the deny is the only difference the next synth meets.
    rc, out = _synth(work, env, expect_rc=None, timeout_s=_SYNTH_TIMEOUT_S)
    assert rc == 0, (
        f"`cdk synth` exited {rc} with the cache intact, even though the lookup role is denied "
        f"ec2:DescribeVpcs; a cached context key must answer the lookup without reaching AWS "
        f"again. Output tail: {out[-1000:]!r}"
    )
    cached_context = json.loads((work / "cdk.context.json").read_text())
    assert cached_context == good_context, (
        f"re-synthesizing from cache resolved {json.dumps(cached_context)[:400]!r}, which "
        f"differs from the first resolution {json.dumps(good_context)[:400]!r} - a cache hit "
        f"must reproduce the first lookup exactly"
    )
    cached_template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    assert cached_template == good_template, (
        "re-synthesizing from cache produced a template that differs from the first synth's, "
        "even though nothing the template depends on changed"
    )

    # 4. CACHE MISS: drop exactly the cached key, leaving the role still denied. The provider
    #    is invoked again, reaches the denied role, and synth fails relaying EC2's refusal.
    _clear_cached_key(work, vpc_keys[0])
    rc, out = _synth(work, env, expect_rc=None, timeout_s=_SYNTH_TIMEOUT_S)
    assert rc != 0, (
        f"`cdk synth` exited 0 after the cached vpc-provider key was removed, even though the "
        f"lookup role is still denied ec2:DescribeVpcs; clearing the cache must force a fresh "
        f"lookup that then fails. Output tail: {out[-1000:]!r}"
    )
    assert all(m in out for m in _DENY_MARKERS) and lookup_role in out, (
        f"the synth failed but the output did not name all of the explicit denial "
        f"{_DENY_MARKERS!r} and the lookup role {lookup_role!r}; output tail: {out[-1200:]!r}"
    )
    miss_context = json.loads((work / "cdk.context.json").read_text())
    assert [k for k in miss_context if k.startswith("vpc-provider:")] == [], (
        f"a vpc-provider context entry was written despite the failed lookup: "
        f"{sorted(miss_context)!r} - a failed lookup must never fabricate a cache entry"
    )

    # The CLI writes no cache entry for a failed lookup; setup for the control arm below.
    # 5. CONTROL: restore the permission, confirm it is back in effect the same way, and
    #    re-run the still-cache-miss synth; the resolution comes back identical to the first.
    _drop_deny(iam, lookup_role)
    _wait_for_describe_vpcs(ctx, lookup_role_arn, vpc_id, want_denied=False)
    _synth(work, env, expect_rc=0, timeout_s=_SYNTH_TIMEOUT_S)
    restored_context = json.loads((work / "cdk.context.json").read_text())
    assert restored_context == good_context, (
        f"control: after restoring the permission, the fresh lookup resolved "
        f"{json.dumps(restored_context)[:400]!r}, which differs from the first resolution - "
        f"the deny was not the only difference between the arms"
    )
    restored_template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    assert restored_template == good_template, (
        "control: the re-synthesized template does not match the first synth's, after "
        "restoring the permission that was the only thing broken"
    )


# ===== helpers (self-contained) =====


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the on-disk CDK app to a temp workdir so cdk.out/cdk.context.json never land in repo."""
    assert app_dir.is_dir(), f"expected a CDK app directory at {app_dir}, found none"
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdklkc-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _usable_az(ec2) -> str:
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert usable, f"this region reports no available AZs: {usable!r}"
    return usable[0]


def _sg_vpc_id(template: dict[str, Any]) -> str:
    sgs = [v for v in template["Resources"].values() if v["Type"] == "AWS::EC2::SecurityGroup"]
    assert len(sgs) == 1, f"template has {len(sgs)} security groups, expected 1"
    return str(sgs[0]["Properties"]["VpcId"])


def _synth_env(ctx, acct: str, qualifier: str, stack: str, tag_value: str) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["VPC_TAG_VALUE"] = tag_value
    return env


def _synth(work: Path, env: dict[str, str], *, expect_rc: int | None,
          timeout_s: float) -> tuple[int, str]:
    cmd = ["cdk", "synth", "--ci", "--no-version-reporting", "--no-notices",
           "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk synth` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _clear_cached_key(work: Path, key: str) -> None:
    """Remove exactly one cached context key, as if it had never been resolved."""
    path = work / "cdk.context.json"
    data = json.loads(path.read_text())
    assert key in data, f"expected cached key {key!r} in {path}, found {sorted(data)!r}"
    del data[key]
    path.write_text(json.dumps(data))


def _wait_for_describe_vpcs(ctx, role_arn: str, vpc_id: str, *, want_denied: bool,
                            budget_s: float = _PERMISSION_PROPAGATION_BUDGET_S,
                            interval_s: float = _PERMISSION_POLL_INTERVAL_S) -> None:
    """Poll DescribeVpcs AS THE ASSUMED LOOKUP ROLE until the permission change is observable.

    Bounded, because an identity-policy change is eventually consistent; never a bare sleep.
    """
    sts = ctx.client("sts")
    deadline = time.monotonic() + budget_s
    last = "never observed"
    while True:
        # A fresh AssumeRole every attempt: a session minted before the policy change must not be
        # read as evidence either way, only the CURRENT permission state matters.
        creds = sts.assume_role(
            RoleArn=role_arn, RoleSessionName="sim2real-cdklkc-probe")["Credentials"]
        assumed = ctx.client("ec2", creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        })
        try:
            assumed.describe_vpcs(VpcIds=[vpc_id])
            last = "succeeded"
            if not want_denied:
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            last = f"ClientError {code!r}"
            # EC2's own code for an explicit-deny or missing-permission call, unlike the
            # "AccessDenied" most other services return. Any OTHER error here is a reason to keep
            # polling, not to raise: it is still eventual-consistency noise, not a verdict.
            if want_denied and code == "UnauthorizedOperation":
                return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"DescribeVpcs through the assumed lookup role never reached "
                f"{'denied' if want_denied else 'allowed'} within {budget_s}s; last observation: "
                f"{last}"
            )
        time.sleep(interval_s)


def _drop_deny(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=_DENY_POLICY_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _bootstrap(ctx, acct: str, qualifier: str, toolkit: str) -> None:
    ctx.verify_account_safety()
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    r = subprocess.run(
        ["cdk", "bootstrap", f"aws://{acct}/{ctx.region}", "--qualifier", qualifier,
         "--toolkit-stack-name", toolkit,
         # AWS_MANAGED_KEY explicitly: an empty value fires the template's CreateNewKey condition
         # and mints a customer CMK with a 7-day irreversible deletion window.
         "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci", "--no-version-reporting",
         "--no-notices"],
        cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _stack_missing(exc: ClientError, stack: str) -> bool:
    """CloudFormation's own answer for a stack that does not exist; anything else is an error."""
    err = exc.response["Error"]
    return (err["Code"] == "ValidationError"
            and f"Stack with id {stack} does not exist" in err.get("Message", ""))


def _delete_stack_and_wait(ctx, stack: str, deadline: float) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if not _stack_missing(exc, stack):
            raise
        return
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not _stack_missing(exc, stack):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        assert status != "DELETE_FAILED", f"stack {stack!r} reached DELETE_FAILED during teardown"
        time.sleep(5.0)
    raise AssertionError(f"stack {stack!r} did not reach DELETE_COMPLETE before the teardown deadline")


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


def _swallow_missing(fn, not_found: str) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != not_found:
            raise


def _delete_vpc_estate(ctx, estate: dict[str, Any], deadline: float) -> None:
    """The one subnet, then the VPC, retrying the VPC while the subnet delete settles."""
    ec2 = ctx.client("ec2")
    if estate.get("subnet"):
        _swallow_missing(lambda: ec2.delete_subnet(SubnetId=estate["subnet"]),
                         "InvalidSubnetID.NotFound")
    if not estate.get("vpc"):
        return
    while True:
        try:
            _swallow_missing(lambda: ec2.delete_vpc(VpcId=estate["vpc"]), "InvalidVpcID.NotFound")
            return
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "DependencyViolation"
                    or time.monotonic() >= deadline):
                raise
        time.sleep(5.0)


def _teardown(ctx, estate: dict[str, Any], acct: str, staging: str, toolkit: str,
              qualifier: str, lookup_role: str) -> None:
    """Delete, then poll until the API says it is gone, and raise naming what remains. The staging
    bucket is deleted explicitly: the bootstrap template retains it on a toolkit delete."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    errors: list[str] = []
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    ecr = ctx.client("ecr")
    repo = f"cdk-{qualifier}-container-assets-{acct}-{ctx.region}"

    for label, fn in (
        ("lookup-role deny", lambda: _drop_deny(iam, lookup_role)),
        ("vpc estate", lambda: _delete_vpc_estate(ctx, estate, deadline)),
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit, deadline)),
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - run every step, then raise naming each failure
            errors.append(f"{label}: {exc!r}")

    # At least one verification pass runs even when a delete step used up the deadline.
    while True:
        remaining: list[str] = []
        # Only each resource's not-found answer means gone; any other error raises at once,
        # naming the step failures collected so far.
        try:
            st = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {st}")
        except ClientError as exc:
            if not _stack_missing(exc, toolkit):
                raise _unverified(errors, "toolkit stack", exc) from exc
        try:
            s3.head_bucket(Bucket=staging)
            remaining.append("staging bucket still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
                raise _unverified(errors, "staging bucket", exc) from exc
        try:
            ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append("bootstrap version parameter still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise _unverified(errors, "bootstrap version parameter", exc) from exc
        try:
            ecr.describe_repositories(repositoryNames=[repo])
            remaining.append(f"ecr repository {repo} still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                raise _unverified(errors, "ecr repository", exc) from exc
        if estate.get("vpc"):
            try:
                ec2.describe_vpcs(VpcIds=[estate["vpc"]])
                remaining.append(f"vpc {estate['vpc']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
                    raise _unverified(errors, "vpc", exc) from exc
        roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
                 for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
        if roles:
            remaining.append(f"bootstrap roles {roles!r}")
        if not remaining:
            break
        if time.monotonic() >= deadline:
            errors.append(f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")
            break
        time.sleep(5.0)
    if errors:
        raise AssertionError(f"{len(errors)} teardown step(s) failed: {'; '.join(errors)}")


def _unverified(errors: list[str], what: str, exc: ClientError) -> AssertionError:
    """The teardown failure for a verification read that answered neither present nor gone."""
    return AssertionError(
        f"teardown could not verify {what} is gone: {exc!r}; step failures: {errors or 'none'}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
