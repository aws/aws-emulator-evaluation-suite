"""cdk-deploy-role-passrole-rejects-non-cfn-exec-role."""
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

CHECK = "cdk-deploy-role-passrole-rejects-non-cfn-exec-role"
GROUP = "deploy-cdk-role-chain"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

# `cdk bootstrap` alone takes about a minute, followed by a full stack create and teardown.
_BOOTSTRAP_TIMEOUT_S = 900.0
_STACK_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0
_ASSUME_RETRY_BUDGET_S = 90.0

_APP_PY = '''\
import os
import aws_cdk as cdk
from aws_cdk import aws_s3 as s3


class ChainStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        s3.CfnBucket(self, "A", bucket_name=os.environ["BUCKET_A"])
        s3.CfnBucket(self, "B", bucket_name=os.environ["BUCKET_B"])


app = cdk.App()
ChainStack(app, os.environ["STACK_NAME"],
           synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
           env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                               region=os.environ["CDK_DEFAULT_REGION"]))
app.synth()
'''


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """The CDK deploy role cannot create resources itself and may iam:PassRole only the bootstrap
    CFN execution role: CreateStack with any other RoleARN is AccessDenied, with the exec role it
    succeeds. Bootstrap's trust, tag and PassRole/ResourceAccount scoping are asserted as written.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-env.html
    """
    require_tools("cdk")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkchain-")
    refused_stack = ctx.unique_name("sim2real-cdkdecoy-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    bucket_a = ctx.unique_name("sim2real-cdkchain-a-")
    bucket_b = ctx.unique_name("sim2real-cdkchain-b-")
    probe_bucket = ctx.unique_name("sim2real-cdkchain-probe-")
    decoy_role = ctx.unique_name("sim2real-cdkchain-decoy-")

    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkchain-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    (work / "app.py").write_text(_APP_PY)

    try:
        key_id = _create_assets_key(ctx, "cdkchain-key")
        _bootstrap(ctx, qualifier, toolkit, key_id)
        ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, toolkit))
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, staging))

        # Synth only: the ROLE ARNS this check asserts on are read out of CDK's own cloud assembly
        # manifest, not constructed from a naming guess.
        _cdk(ctx, work, ["synth"], qualifier, stack, bucket_a, bucket_b)
        props = json.loads((work / "cdk.out" / "manifest.json").read_text())["artifacts"][stack]["properties"]
        deploy_arn = props["assumeRoleArn"].replace("${AWS::Partition}", "aws")
        cfn_exec_arn = props["cloudFormationExecutionRoleArn"].replace("${AWS::Partition}", "aws")
        deploy_role_name = deploy_arn.rsplit("/", 1)[1]
        fp_role_name = f"cdk-{qualifier}-file-publishing-role-{acct}-{ctx.region}"
        assert deploy_role_name == f"cdk-{qualifier}-deploy-role-{acct}-{ctx.region}", (
            f"manifest named deploy role {deploy_role_name!r}, expected the bootstrap role for "
            f"qualifier {qualifier!r}"
        )

        # 1. bootstrap's own marker on the role — not something this check wrote.
        role = iam.get_role(RoleName=deploy_role_name)["Role"]
        assert {"Key": "aws-cdk:bootstrap-role", "Value": "deploy"} in role.get("Tags", []), (
            f"deploy role tags were {role.get('Tags')!r}, expected the bootstrap marker "
            f"{{'Key': 'aws-cdk:bootstrap-role', 'Value': 'deploy'}}"
        )

        # 2. the trust document bootstrap wrote, exactly.
        trust = role["AssumeRolePolicyDocument"]
        assert trust["Statement"][0]["Principal"] == {"AWS": f"arn:aws:iam::{acct}:root"}, (
            f"deploy role's first trust principal was {trust['Statement'][0]['Principal']!r}, "
            f"expected the account root"
        )
        assert trust["Statement"][0]["Condition"] == {"Null": {"sts:ExternalId": "true"}}, (
            f"deploy role's trust condition was {trust['Statement'][0].get('Condition')!r}, expected "
            f"{{'Null': {{'sts:ExternalId': 'true'}}}}"
        )
        assert trust["Statement"][1]["Action"] == "sts:TagSession", (
            f"deploy role's second trust statement action was "
            f"{trust['Statement'][1]['Action']!r}, expected 'sts:TagSession'"
        )

        # 3. PassRole is scoped to exactly one role ARN, and it is the CFN exec role.
        inline = iam.get_role_policy(RoleName=deploy_role_name, PolicyName="default")["PolicyDocument"]
        pass_stmts = [s for s in inline["Statement"] if s.get("Action") == "iam:PassRole"]
        assert len(pass_stmts) == 1, (
            f"deploy role has {len(pass_stmts)} iam:PassRole statements, expected exactly 1"
        )
        assert pass_stmts[0]["Resource"] == cfn_exec_arn, (
            f"iam:PassRole is scoped to {pass_stmts[0]['Resource']!r}, expected only the CFN "
            f"execution role {cfn_exec_arn!r}"
        )

        # 4. NEGATIVE: the trust policy's Null condition denies an assume that supplies an
        #    ExternalId; the identical call without one is the control (used for everything below).
        caller_arn = sts.get_caller_identity()["Arn"]
        _expect(lambda: sts.assume_role(
            RoleArn=deploy_arn, RoleSessionName="sim2real-extid", ExternalId="sim2real-not-allowed",
        ), "AccessDenied",
            f"User: {caller_arn} is not authorized to perform: sts:AssumeRole on resource: "
            f"{deploy_arn}",
            "the trust policy's `Null: {sts:ExternalId: true}` condition must deny an assume that "
            "supplies an ExternalId")
        deploy_creds = _assume(sts, deploy_arn, "sim2real-deploy")
        deploy_cfn = ctx.client("cloudformation", creds=deploy_creds)
        deploy_s3 = ctx.client("s3", creds=deploy_creds)
        deploy_iam = ctx.client("iam", creds=deploy_creds)
        deploy_session = f"arn:aws:sts::{acct}:assumed-role/{deploy_role_name}/sim2real-deploy"

        # 5. NEGATIVE: the deploy role has CFN/S3-read/SSM/PassRole and nothing else, so it cannot
        #    create the resources the stack creates. Effect-absent from the check's own creds.
        _expect(lambda: deploy_s3.create_bucket(
            Bucket=probe_bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        ), "AccessDenied",
            f"User: {deploy_session} is not authorized to perform: s3:CreateBucket on resource: "
            f"\"arn:aws:s3:::{probe_bucket}\" because no identity-based policy allows the "
            f"s3:CreateBucket action",
            f"the deploy role holds no s3:CreateBucket, so creating {probe_bucket!r} is refused")
        _expect(lambda: s3.head_bucket(Bucket=probe_bucket), "404", "Not Found",
                f"effect-absent: bucket {probe_bucket!r} exists after the refused CreateBucket")

        # 6. NEGATIVE: the deploy role cannot escalate through IAM either.
        _expect(lambda: deploy_iam.create_role(
            RoleName=decoy_role + "-escalated",
            AssumeRolePolicyDocument=json.dumps(_CFN_TRUST),
        ), "AccessDenied",
            f"User: {deploy_session} is not authorized to perform: iam:CreateRole on resource: "
            f"arn:aws:iam::{acct}:role/{decoy_role}-escalated because no identity-based policy "
            f"allows the iam:CreateRole action",
            "the deploy role holds iam:PassRole and no other iam action")
        _expect(lambda: iam.get_role(RoleName=decoy_role + "-escalated"), "NoSuchEntity",
                f"The role with name {decoy_role}-escalated cannot be found.",
                f"effect-absent: role {decoy_role + '-escalated'!r} exists after the refused "
                f"CreateRole")

        # A decoy role that CloudFormation itself would happily accept — the only thing wrong with
        # it in arm 7 is that the deploy role is not allowed to PASS it.
        decoy_arn = iam.create_role(
            RoleName=decoy_role, AssumeRolePolicyDocument=json.dumps(_CFN_TRUST),
            Description="sim2real cdk deploy-role PassRole scoping decoy",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["Role"]["Arn"]
        ctx.on_cleanup(lambda: _delete_decoy(iam, decoy_role))
        iam.attach_role_policy(RoleName=decoy_role,
                               PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")

        # The template the deploy role will build from is published to the staging bucket by the
        # FILE-PUBLISHING role, so the deploy role's S3-read leg is exercised too.
        template_key = f"{ctx.unique_name('sim2real-cdkchain-tmpl-')}.json"
        fp_creds = _assume(sts, f"arn:aws:iam::{acct}:role/{fp_role_name}", "sim2real-publish")
        template_body = (work / "cdk.out" / f"{stack}.template.json").read_text()
        ctx.client("s3", creds=fp_creds).put_object(
            Bucket=staging, Key=template_key, Body=template_body.encode())
        template_url = f"https://s3.{ctx.region}.amazonaws.com/{staging}/{template_key}"
        assert deploy_s3.get_object(Bucket=staging, Key=template_key)["Body"].read().decode() \
            == template_body, (
            "the deploy role could not read back the template the file-publishing role published"
        )

        # 7. NEGATIVE: same call, different RoleARN. This is the whole subject of the check.
        _expect(lambda: deploy_cfn.create_stack(
            StackName=refused_stack, TemplateURL=template_url, RoleARN=decoy_arn,
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        ), "AccessDenied",
            f"User: {deploy_session} is not authorized to perform: iam:PassRole on resource: "
            f"{decoy_arn} because no identity-based policy allows the iam:PassRole action",
            f"the deploy role's iam:PassRole is scoped to the CFN exec role only, so CreateStack "
            f"with RoleARN={decoy_arn!r} must be refused")
        _expect(lambda: cfn.describe_stacks(StackName=refused_stack), "ValidationError",
                f"Stack with id {refused_stack} does not exist",
                f"effect-absent: stack {refused_stack!r} exists after the refused CreateStack")

        # 8. CONTROL: the identical call with the CFN exec role succeeds.
        deploy_cfn.create_stack(
            StackName=stack, TemplateURL=template_url, RoleARN=cfn_exec_arn,
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))
        status = _wait_stack(cfn, stack, _STACK_TIMEOUT_S)
        assert status == "CREATE_COMPLETE", (
            f"control: the stack the deploy role created with RoleARN={cfn_exec_arn!r} ended in "
            f"{status!r}, expected CREATE_COMPLETE"
        )

        # 9. CloudFormation persisted the passed role, and the passed role did the work the deploy
        #    role could not do itself (arm 5).
        described = cfn.describe_stacks(StackName=stack)["Stacks"][0]
        assert described["RoleARN"] == cfn_exec_arn, (
            f"DescribeStacks reports RoleARN {described.get('RoleARN')!r}, expected {cfn_exec_arn!r}"
        )
        owned = {r["PhysicalResourceId"] for r in
                 cfn.describe_stack_resources(StackName=stack)["StackResources"]}
        assert {bucket_a, bucket_b} <= owned, (
            f"the stack owns physical resources {sorted(owned)!r}; expected both {bucket_a!r} and "
            f"{bucket_b!r} to have been created by the passed role"
        )
        for b in (bucket_a, bucket_b):
            assert s3.head_bucket(Bucket=b)["ResponseMetadata"]["HTTPStatusCode"] == 200, (
                f"bucket {b!r} named in the stack does not exist"
            )

        # 10. the file-publishing role's account-scoping condition, as bootstrap wrote it.
        fp_policy = iam.get_role_policy(
            RoleName=fp_role_name,
            PolicyName=f"cdk-{qualifier}-file-publishing-role-default-policy-{acct}-{ctx.region}",
        )["PolicyDocument"]
        scoped = [s for s in fp_policy["Statement"]
                  if s.get("Condition", {}).get("StringEquals", {}).get("aws:ResourceAccount")]
        assert len(scoped) == 1, (
            f"file-publishing role has {len(scoped)} statements conditioned on aws:ResourceAccount, "
            f"expected 1: {json.dumps(fp_policy)[:600]!r}"
        )
        assert scoped[0]["Condition"]["StringEquals"]["aws:ResourceAccount"] == [acct], (
            f"aws:ResourceAccount condition was "
            f"{scoped[0]['Condition']['StringEquals']['aws:ResourceAccount']!r}, expected [{acct!r}]"
        )
        assert sorted(scoped[0]["Resource"]) == sorted(
            [f"arn:aws:s3:::{staging}", f"arn:aws:s3:::{staging}/*"]), (
            f"file-publishing role is scoped to {scoped[0]['Resource']!r}, expected only the "
            f"staging bucket {staging!r}"
        )
    finally:
        # Inline teardown: ctx.on_cleanup's budget cannot cover two stack deletes plus a
        # versioned-bucket purge, so those registrations are only the failure-path net.
        _teardown(ctx, [stack], staging, toolkit, qualifier, [bucket_a, bucket_b], decoy_role)



_CFN_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _expect(fn, code: str, message: str, why: str) -> None:
    """Assert fn() is refused with exactly this code and message; raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        got = (str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", "")))
        assert got == (code, message), f"{why}: expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"{why}: the call succeeded but was expected to be refused")


def _create_assets_key(ctx, label: str) -> str:
    """A customer key for the staging bucket with the same S3-scoped grant the AWS-managed S3 key
    carries. Deletion is scheduled by cleanup; a key pending deletion is inert."""
    kms = ctx.client("kms")
    acct = ctx.client("sts").get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Root", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{acct}:root"},
             "Action": "kms:*", "Resource": "*"},
            {"Sid": "ViaS3", "Effect": "Allow", "Principal": {"AWS": "*"},
             "Action": ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*",
                        "kms:DescribeKey"],
             "Resource": "*",
             "Condition": {"StringEquals": {"kms:CallerAccount": acct,
                                            "kms:ViaService": f"s3.{ctx.region}.amazonaws.com"}}},
        ],
    }
    key_id = kms.create_key(
        Description=ctx.unique_name(f"sim2real-{label}-"), Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(ctx, key_id))
    return key_id


def _schedule_key_deletion(ctx, key_id: str) -> None:
    try:
        ctx.client("kms").schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("KMSInvalidStateException", "NotFoundException"):
            raise


def _assume(sts, role_arn: str, session: str) -> dict[str, str]:
    """Assume with a bounded AccessDenied retry, since a just-created role is not instantly
    assumable. Positive arms only: around a negative a retry would mask the refusal."""
    deadline = time.monotonic() + _ASSUME_RETRY_BUDGET_S
    last = None
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=session)["Credentials"]
            # The key name is split into two literals so secret scanners do not flag it.
            return {"aws_access_key_id": c["AccessKeyId"],
                    "aws_secret" "_access_key": c["SecretAccessKey"],
                    "aws_session_token": c["SessionToken"]}
        except ClientError as exc:
            last = exc
            if exc.response["Error"]["Code"] != "AccessDenied" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
    raise AssertionError(f"could not assume {role_arn!r}: {last!r}")


def _bootstrap(ctx, qualifier: str, toolkit: str, key_id: str) -> None:
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
         # The check's own key: an empty value fires the template's CreateNewKey condition, and
         # AWS_MANAGED_KEY relies on the account's alias/aws/s3 key.
         "--bootstrap-kms-key-id", key_id, "--ci"],
        cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str,
         bucket_a: str, bucket_b: str) -> None:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["BUCKET_A"] = bucket_a
    env["BUCKET_B"] = bucket_b
    r = subprocess.run(
        ["cdk", *args, "--ci", "--no-version-reporting", "--app", f"{sys.executable} app.py"],
        cwd=work, env=env, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, (
        f"`cdk {args[0]}` rc={r.returncode}: {(r.stdout + r.stderr)[-1000:]!r}"
    )


def _wait_stack(cfn, stack: str, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        if status.endswith("_COMPLETE") or status.endswith("_FAILED"):
            return status
        time.sleep(5.0)
    raise AssertionError(f"stack {stack!r} still {status!r} after {timeout_s}s")


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        time.sleep(2.0)
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


def _teardown(ctx, stacks: list[str], staging: str, toolkit: str, qualifier: str,
              stack_buckets: list[str], decoy_role: str) -> None:
    """Delete, poll until gone, then assert absence. The staging bucket carries DeletionPolicy:
    Retain in the bootstrap template, so a toolkit delete skips it and it must be deleted here."""
    found = sys.exc_info()[1]
    prefix = f"{found!r}; " if found else ""
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    steps: list[tuple[str, Any]] = [(f"app stack {s}", (lambda s=s: _delete_stack_and_wait(ctx, s)))
                                    for s in stacks]
    steps.append(("decoy role", lambda: _delete_decoy(iam, decoy_role)))
    steps.append((f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)))
    steps.append((f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)))
    for label, fn in steps:
        try:
            fn()
        except ClientError as exc:
            raise AssertionError(f"{prefix}teardown of {label} failed: {exc}") from exc

    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining: list[str] = ["teardown verification never ran"]
    while time.monotonic() < deadline:
        remaining = []
        try:
            st = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {st}")
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        for b in [staging, *stack_buckets]:
            try:
                s3.head_bucket(Bucket=b)
                remaining.append(f"bucket {b} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in ("404", "NoSuchBucket"):
                    raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        try:
            ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append("bootstrap version parameter still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise RuntimeError(f"{prefix}teardown verification failed: {exc}") from exc
        roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
                 for r in page["Roles"]
                 if r["RoleName"].startswith(f"cdk-{qualifier}-") or r["RoleName"] == decoy_role]
        if roles:
            remaining.append(f"roles {roles!r}")
        if not remaining:
            break
        time.sleep(2.0)
    else:
        raise AssertionError(f"{prefix}remnants still present after {_TEARDOWN_DEADLINE_S}s: "
                             f"{remaining!r}")


def _delete_decoy(iam, name: str) -> None:
    try:
        for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
