"""cdk-bootstrap-asset-deploy-is-content-addressed."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-bootstrap-asset-deploy-is-content-addressed"
GROUP = "deploy-cdk-asset-publishing"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

# `cdk bootstrap` takes ~52s and each `cdk deploy` ~40s; with four deploys and an inline teardown
# the check needs minutes, and these declared budgets size its overall deadline.
_BOOTSTRAP_TIMEOUT_S = 900.0
_DEPLOY_TIMEOUT_S = 900.0
_TEARDOWN_DEADLINE_S = 420.0

_APP_PY = '''\
import os
import aws_cdk as cdk
from aws_cdk import aws_lambda as _lambda


class AssetStack(cdk.Stack):
    def __init__(self, scope, sid, **kw):
        super().__init__(scope, sid, **kw)
        fn = _lambda.Function(
            self, "Echo",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset("handler"),
            timeout=cdk.Duration.seconds(30),
        )
        cdk.CfnOutput(self, "FunctionName", value=fn.function_name)


app = cdk.App()
AssetStack(app, os.environ["STACK_NAME"],
           synthesizer=cdk.DefaultStackSynthesizer(qualifier=os.environ["Q"]),
           env=cdk.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                               region=os.environ["CDK_DEFAULT_REGION"]))
app.synth()
'''

_HANDLER_PY = '''\
def handler(event, context):
    return {"marker": "%s", "n": len(event.get("items", []))}
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy",
      "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CDK file asset is published under the SHA-256 of its content, the template and Lambda use
    that key, a no-change re-deploy adds no object version, and a denied publish adds nothing.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
    """
    require_tools("cdk")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkasset-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"

    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkasset-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    (work / "handler").mkdir()
    (work / "cdk.json").write_text(json.dumps({"app": f"{sys.executable} app.py"}))
    (work / "app.py").write_text(_APP_PY)

    marker1 = ctx.unique_name("m1-")
    _write_handler(work, marker1)

    try:
        key_id = _create_assets_key(ctx, "cdkasset-key")
        _bootstrap(ctx, qualifier, toolkit, key_id)
        ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, toolkit))
        ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, staging))

        _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
             qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

        assets = json.loads((work / "cdk.out" / f"{stack}.assets.json").read_text())
        files = assets["files"]
        code_hash = _code_hash(files)
        tmpl_hash = _template_hash(files, stack)

        # 1. exactly the two assets CDK is contracted to publish, and the code key is a sha256.
        assert set(files) == {code_hash, tmpl_hash}, (
            f"assets manifest listed {sorted(files)!r}, expected exactly the code asset "
            f"{code_hash!r} and the template asset {tmpl_hash!r}"
        )
        assert len(code_hash) == 64 and all(c in "0123456789abcdef" for c in code_hash), (
            f"code asset id {code_hash!r} is not 64 lowercase hex — it is not a content hash"
        )

        # 2. the destination bucket is the one bootstrap had to CREATE under this qualifier.
        dest = next(iter(files[code_hash]["destinations"].values()))
        assert dest["bucketName"] == staging, (
            f"asset destination bucket was {dest['bucketName']!r}, expected the bootstrap staging "
            f"bucket {staging!r} for qualifier {qualifier!r}"
        )
        assert dest["objectKey"] == f"{code_hash}.zip", (
            f"asset objectKey was {dest['objectKey']!r}, expected {code_hash + '.zip'!r}"
        )

        # 3./4. the published object is the asset's own bytes, byte-for-byte.
        local_zip = (work / "cdk.out" / f"asset.{code_hash}.zip")
        local_bytes = local_zip.read_bytes() if local_zip.is_file() else None
        head1 = s3.head_object(Bucket=staging, Key=f"{code_hash}.zip")
        published = s3.get_object(Bucket=staging, Key=f"{code_hash}.zip")["Body"].read()
        assert head1["ContentLength"] == len(published), (
            f"HeadObject reported ContentLength {head1['ContentLength']!r} but GetObject returned "
            f"{len(published)!r} bytes"
        )
        if local_bytes is not None:
            assert local_bytes == published, (
                f"published object is {len(published)} bytes but the local asset zip is "
                f"{len(local_bytes)} bytes — the bytes at the content-addressed key are not the "
                f"asset's bytes"
            )
        inner = zipfile.ZipFile(io.BytesIO(published))
        assert inner.namelist() == ["index.py"], (
            f"published zip contains {inner.namelist()!r}, expected exactly ['index.py']"
        )
        assert inner.read("index.py") == (work / "handler" / "index.py").read_bytes(), (
            "the index.py inside the published zip is not the handler source this check wrote"
        )

        # 5. the deployed template points at exactly that key.
        code_prop = _template_code_property(cfn, stack)
        assert code_prop == {"S3Bucket": staging, "S3Key": f"{code_hash}.zip"}, (
            f"deployed template's Lambda Code was {code_prop!r}, expected "
            f"{{'S3Bucket': {staging!r}, 'S3Key': {code_hash + '.zip'!r}}}"
        )

        # 6. the code at that key is the code that runs.
        fn_name = json.loads((work / "out.json").read_text())[stack]["FunctionName"]
        # Lambda creates the function's log group on first invoke; the stack does not own it.
        ctx.on_cleanup(lambda: _delete_log_group(ctx, f"/aws/lambda/{fn_name}"))
        payload = _invoke(lam, fn_name, {"items": [1, 2, 3]})
        assert payload == {"marker": marker1, "n": 3}, (
            f"invoke returned {payload!r}, expected {{'marker': {marker1!r}, 'n': 3}} — the bytes "
            f"at the content-addressed key are not what Lambda executed"
        )

        # 7. Lambda independently hashed the same bytes.
        want_sha = base64.b64encode(hashlib.sha256(published).digest()).decode()
        got_sha = lam.get_function(FunctionName=fn_name)["Configuration"]["CodeSha256"]
        assert got_sha == want_sha, (
            f"Lambda reports CodeSha256 {got_sha!r} but the published zip hashes to {want_sha!r} — "
            f"the service did not hash the object it was given"
        )

        # 8. THE KEYSTONE: a no-change re-deploy must not re-upload.
        before = _versions(s3, staging, f"{code_hash}.zip")
        assert len(before) == 1, f"expected 1 version of the code asset before re-deploy, got {before!r}"
        _cdk(ctx, work, ["deploy", "--require-approval", "never"], qualifier, stack,
             timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        after = _versions(s3, staging, f"{code_hash}.zip")
        assert after == before, (
            f"a no-change `cdk deploy` changed the staging object's version history from {before!r} "
            f"to {after!r} — an identical asset must not be re-uploaded and an identical PUT must "
            f"not mint a new VersionId"
        )

        # 9. one byte of source -> a different key, both objects present, new behaviour.
        marker2 = ctx.unique_name("m2-")
        _write_handler(work, marker2)
        _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
             qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        files2 = json.loads((work / "cdk.out" / f"{stack}.assets.json").read_text())["files"]
        code_hash2 = _code_hash(files2)
        assert code_hash2 != code_hash, (
            f"a changed handler produced the same asset key {code_hash2!r} — the key is not derived "
            f"from content"
        )
        assert s3.head_object(Bucket=staging, Key=f"{code_hash2}.zip")["ContentLength"] > 0, (
            f"the new asset {code_hash2!r} was not published"
        )
        assert s3.head_object(Bucket=staging, Key=f"{code_hash}.zip")["ContentLength"] == \
            head1["ContentLength"], (
            f"the original asset {code_hash!r} was clobbered by the new deploy"
        )
        payload2 = _invoke(lam, fn_name, {"items": [1, 2]})
        assert payload2 == {"marker": marker2, "n": 2}, (
            f"after the source change invoke returned {payload2!r}, expected marker {marker2!r}"
        )

        # 10. NEGATIVE: deny the file-publishing role's PutObject, then change the source. The
        #     publish must be refused, and the third asset must never appear.
        fp_role = f"arn:aws:iam::{acct}:role/cdk-{qualifier}-file-publishing-role-{acct}-{ctx.region}"
        original_policy = s3.get_bucket_policy(Bucket=staging)["Policy"]
        denied = json.loads(original_policy)
        denied["Statement"].append({
            "Sid": "Sim2realDenyAssetPublish", "Effect": "Deny",
            "Principal": {"AWS": fp_role}, "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{staging}/*",
        })
        s3.put_bucket_policy(Bucket=staging, Policy=json.dumps(denied))
        ctx.on_cleanup(lambda: _restore_bucket_policy(s3, staging, original_policy))

        marker3 = ctx.unique_name("m3-")
        _write_handler(work, marker3)
        rc, out = _cdk(ctx, work, ["deploy", "--require-approval", "never"], qualifier, stack,
                       timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=None)
        assert rc != 0, (
            f"`cdk deploy` exited 0 while the file-publishing role was denied s3:PutObject on the "
            f"staging bucket — the publish was accepted. Output tail: {out[-400:]!r}"
        )
        # The CLI surfaces the S3 authorization failure verbatim rather than a bare error code.
        assert "s3:PutObject" in out and "explicit deny in a resource-based policy" in out, (
            f"deploy failed but not with the bucket policy's explicit deny on s3:PutObject; output "
            f"tail: {out[-600:]!r}"
        )
        assert f"cdk-{qualifier}-file-publishing-role" in out, (
            f"the refusal did not name the file-publishing role as the denied principal; output "
            f"tail: {out[-600:]!r}"
        )
        files3 = json.loads((work / "cdk.out" / f"{stack}.assets.json").read_text())["files"]
        code_hash3 = _code_hash(files3)
        assert code_hash3 not in (code_hash, code_hash2), (
            f"the third handler hashed to an already-published key {code_hash3!r}"
        )
        assert _error(
            lambda: s3.head_object(Bucket=staging, Key=f"{code_hash3}.zip")
        ) == ("404", "Not Found"), (
            f"effect-absent: object {code_hash3 + '.zip'!r} exists even though the publish was denied"
        )
        payload3 = _invoke(lam, fn_name, {"items": []})
        assert payload3 == {"marker": marker2, "n": 0}, (
            f"the function's code changed despite the refused publish: invoke returned {payload3!r}, "
            f"expected the previous marker {marker2!r}"
        )

        # 11. CONTROL: remove the deny, redeploy the identical source, the third asset lands.
        s3.put_bucket_policy(Bucket=staging, Policy=original_policy)
        _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
             qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0,
             retry_on="AccessDenied")
        assert s3.head_object(Bucket=staging, Key=f"{code_hash3}.zip")["ContentLength"] > 0, (
            f"control: asset {code_hash3!r} still absent after the deny was removed — the deny arm "
            f"was not the cause"
        )
        payload4 = _invoke(lam, fn_name, {"items": [7]})
        assert payload4 == {"marker": marker3, "n": 1}, (
            f"control: invoke returned {payload4!r}, expected marker {marker3!r}"
        )
    finally:
        # Inline teardown: two stack deletes plus a versioned-bucket purge outlast the cleanup cap.
        _teardown(ctx, stack, staging, toolkit, qualifier, acct)


def _write_handler(work: Path, marker: str) -> None:
    (work / "handler" / "index.py").write_text(_HANDLER_PY % marker)


def _code_hash(files: dict[str, Any]) -> str:
    ids = [k for k, v in files.items() if v.get("displayName") == "Echo/Code"]
    assert len(ids) == 1, f"expected one 'Echo/Code' file asset, manifest had {ids!r}"
    return ids[0]


def _template_hash(files: dict[str, Any], stack: str) -> str:
    ids = [k for k, v in files.items()
           if v.get("source", {}).get("path") == f"{stack}.template.json"]
    assert len(ids) == 1, f"expected one template file asset for {stack!r}, manifest had {ids!r}"
    return ids[0]


def _error(fn) -> tuple[str, str]:
    """The AWS (code, message) a call raises; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return str(exc.response["Error"]["Code"]), str(exc.response["Error"].get("Message", ""))
    raise AssertionError("call succeeded but was expected to be refused")


def _create_assets_key(ctx, label: str) -> str:
    """A customer key for the staging bucket with the S3-scoped grant the AWS-managed S3 key has.

    Deletion is scheduled by cleanup; a key pending deletion is inert."""
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


def _delete_log_group(ctx, name: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _restore_bucket_policy(s3, bucket: str, policy: str) -> None:
    """Failure-path net; the inline teardown deletes the bucket first on the normal path."""
    try:
        s3.put_bucket_policy(Bucket=bucket, Policy=policy)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _versions(s3, bucket: str, key: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
        for v in page.get("Versions", []):
            if v["Key"] == key:
                found.append((v["VersionId"], v["LastModified"].isoformat()))
    return sorted(found)


def _invoke(lam, fn_name: str, event: dict[str, Any]) -> Any:
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(event).encode())
    assert "FunctionError" not in resp, (
        f"invoke of {fn_name!r} errored: {resp['Payload'].read()[:400]!r}"
    )
    return json.loads(resp["Payload"].read())


def _template_code_property(cfn, stack: str) -> dict[str, Any]:
    body = cfn.get_template(StackName=stack)["TemplateBody"]
    doc = json.loads(body) if isinstance(body, str) else json.loads(json.dumps(body))
    fns = [v for v in doc["Resources"].values() if v["Type"] == "AWS::Lambda::Function"]
    assert len(fns) == 1, f"deployed template has {len(fns)} Lambda functions, expected 1"
    return dict(fns[0]["Properties"]["Code"])


def _cdk_env(ctx, qualifier: str, stack: str) -> dict[str, str]:
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    return env


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
    cmd = [
        "cdk", "bootstrap", f"aws://{acct}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit,
        # The check's own key: an EMPTY value fires the template's CreateNewKey condition, and
        # AWS_MANAGED_KEY relies on the account's alias/aws/s3 key.
        "--bootstrap-kms-key-id", key_id, "--ci",
        # The staging bucket's name does not carry the sim2real prefix, so tag it via the stack.
        "--tags", f"sim2real={CHECK}",
    ]
    r = subprocess.run(cmd, cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
                       timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, *, timeout_s: float,
         expect_rc: int | None, retry_on: str | None = None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = _cdk_env(ctx, qualifier, stack)
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--app", f"{sys.executable} app.py"]
    deadline = time.monotonic() + timeout_s
    out = ""
    rc = -1
    while True:
        r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True,
                           timeout=max(30.0, deadline - time.monotonic()))
        rc, out = r.returncode, r.stdout + r.stderr
        # A bounded retry for the POSITIVE arms only: an S3 bucket policy change is eventually
        # consistent, so a control arm may see the just-removed deny once. Never used on a
        # negative arm, where a retry would hide the refusal behind a timing artifact.
        if rc == 0 or retry_on is None or retry_on not in out or time.monotonic() >= deadline:
            break
        time.sleep(2)
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


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


def _teardown(ctx, stack: str, staging: str, toolkit: str, qualifier: str, acct: str) -> None:
    """Delete each resource, poll until gone, and assert the absence.

    The staging bucket has DeletionPolicy: Retain (DELETE_SKIPPED on a toolkit delete), so it is
    deleted explicitly here."""
    found = sys.exc_info()[1]
    prefix = f"{found!r}; " if found else ""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    for label, fn in (
        (f"app stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        try:
            fn()
        except ClientError as exc:
            raise AssertionError(f"{prefix}teardown of {label} failed: {exc}") from exc

    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")
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
        try:
            s3.head_bucket(Bucket=staging)
            remaining.append("staging bucket still present")
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
                 for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
        if roles:
            remaining.append(f"bootstrap roles {roles!r}")
        if not remaining:
            break
        time.sleep(2.0)
    else:
        raise AssertionError(f"{prefix}bootstrap remnants still present after {_TEARDOWN_DEADLINE_S}s: "
                             f"{remaining!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
