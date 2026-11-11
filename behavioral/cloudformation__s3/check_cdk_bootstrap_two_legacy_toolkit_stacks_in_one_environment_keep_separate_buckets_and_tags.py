"""cdk-bootstrap-two-legacy-toolkit-stacks-in-one-environment-keep-separate-buckets-and-tags."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-bootstrap-two-legacy-toolkit-stacks-in-one-environment-keep-separate-buckets-and-tags"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_SHOW_TEMPLATE_TIMEOUT_S = 60.0
# A cdk step ends this long before the runner's budget, so it fails with its own message.
_RESERVE_S = 15.0
_TEARDOWN_S = 420.0
_POLL_S = 5.0
_CDK_FLAGS = ("--ci", "--no-version-reporting", "--no-notices", "--no-color")
_NO_SUCH_KEY = ("NoSuchKey", "The specified key does not exist.")


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """Two legacy toolkit stacks, one tagged, coexist in one environment, each with its own bucket.

    Only the tagged stack and its bucket carry the tags; an object written to one bucket is
    absent from the other.
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")
    s3 = ctx.client("s3")
    base = ctx.unique_name("sim2real-cdkleg-")
    first, second = f"{base}-1", f"{base}-2"
    scratch = _scratch(ctx, "sim2real-cdkboot-")

    # 1. two bootstraps into the same environment. Teardowns first, so part-way stacks go too.
    ctx.on_cleanup(lambda: _teardown_legacy(ctx, first))
    ctx.on_cleanup(lambda: _teardown_legacy(ctx, second))
    _bootstrap_legacy(ctx, scratch, first, "--tags", "Foo=Bar", "--tags", f"sim2real={CHECK}")
    _bootstrap_legacy(ctx, scratch, second)

    # 2. each stack and bucket as CloudFormation and S3 report them
    first_bucket = _assert_legacy_toolkit(
        ctx,
        first,
        user_tags=sorted([("Foo", "Bar"), ("sim2real", CHECK)]),
        public_access_block=True,
    )
    second_bucket = _assert_legacy_toolkit(ctx, second, user_tags=[], public_access_block=True)
    assert first_bucket != second_bucket, f"both toolkit stacks name bucket {first_bucket!r}"

    # 3. the buckets are separate stores
    key, body = ctx.unique_name("probe/"), ctx.unique_name("marker-").encode()
    s3.put_object(Bucket=first_bucket, Key=key, Body=body)
    assert s3.get_object(Bucket=first_bucket, Key=key)["Body"].read() == body, (
        f"s3://{first_bucket}/{key} does not read back as written"
    )
    error = _client_error(lambda: s3.get_object(Bucket=second_bucket, Key=key)).response["Error"]
    assert (error["Code"], error.get("Message")) == _NO_SUCH_KEY, (
        f"GetObject of {key!r} from the other toolkit bucket {second_bucket!r} answered {error!r}, "
        f"expected {_NO_SUCH_KEY!r}"
    )


def _scratch(ctx, prefix: str) -> Path:
    """A temp dir of this check's own, removed after it."""
    path = Path(tempfile.mkdtemp(prefix=prefix))
    ctx.on_cleanup(lambda: shutil.rmtree(path, ignore_errors=True))
    return path


def _run_cdk(
    ctx, cwd: Path, args: list[str], *, timeout_s: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess:
    """Run the CDK CLI in *cwd* and require exit code 0."""
    ctx.verify_account_safety()
    full_env = ctx.subprocess_env()
    full_env.update(env or {})
    result = subprocess.run(
        ["cdk", *args, *_CDK_FLAGS],
        cwd=cwd,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=_step_timeout(ctx, timeout_s),
    )
    assert result.returncode == 0, (
        f"`cdk {' '.join(args[:2])}` exited {result.returncode}, expected 0; output tail: "
        f"{(result.stdout + result.stderr)[-1500:]!r}"
    )
    return result


def _user_tags(tags: list[dict[str, str]]) -> list[tuple[str, str]]:
    """Tags as sorted (key, value) pairs, without the `aws:` keys AWS reserves for itself."""
    return sorted((t["Key"], t["Value"]) for t in tags if not t["Key"].startswith("aws:"))


def _client_error(fn) -> ClientError:
    """The ClientError a call raises."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("the call succeeded but was expected to be refused")


def _stack_missing(exc: ClientError, stack: str) -> bool:
    error = exc.response["Error"]
    return (error["Code"], error.get("Message")) in (
        ("ValidationError", f"Stack with id {stack} does not exist"),
        ("ValidationError", f"Stack [{stack}] does not exist"),
    )


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if _stack_missing(exc, stack):
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED")
        time.sleep(_POLL_S)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _empty_bucket(ctx, bucket: str) -> None:
    """Purge every object version and delete marker of *bucket*."""
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})


def _bucket_absent(ctx, bucket: str) -> bool:
    try:
        ctx.client("s3").head_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("404", "NoSuchBucket"):
            return True
        raise
    return False


def _template_dict(body: Any) -> dict[str, Any]:
    """A GetTemplate body as a dict: the SDK decodes a JSON body, a YAML body arrives as text."""
    return body if isinstance(body, dict) else yaml.safe_load(body)


def _bootstrap_legacy(ctx, cwd: Path, toolkit: str, *flags: str) -> str:
    """`cdk bootstrap` with the legacy template (`CDK_LEGACY_BOOTSTRAP`); returns its output."""
    result = _run_cdk(
        ctx,
        cwd,
        ["bootstrap", f"aws://{ctx.account}/{ctx.region}", "--toolkit-stack-name", toolkit, *flags],
        timeout_s=_BOOTSTRAP_TIMEOUT_S,
        env={"CDK_LEGACY_BOOTSTRAP": "1"},
    )
    return result.stdout + result.stderr


def _legacy_bucket(ctx, toolkit: str) -> str | None:
    """The staging bucket's physical name, or None while the stack or the bucket is absent."""
    try:
        detail = ctx.client("cloudformation").describe_stack_resource(
            StackName=toolkit, LogicalResourceId="StagingBucket"
        )["StackResourceDetail"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError":
            return None
        raise
    return detail.get("PhysicalResourceId") or None


def _teardown_legacy(ctx, toolkit: str) -> None:
    """Empty the stack's staging bucket, delete the stack, and require the bucket gone."""
    bucket = _legacy_bucket(ctx, toolkit)
    if bucket and not _bucket_absent(ctx, bucket):
        _empty_bucket(ctx, bucket)
    _delete_stack_and_wait(ctx, toolkit, timeout_s=_TEARDOWN_S)
    if bucket and not _bucket_absent(ctx, bucket):
        raise AssertionError(f"legacy staging bucket {bucket!r} survived its stack's deletion")


def _assert_legacy_toolkit(
    ctx, toolkit: str, *, user_tags: list[tuple[str, str]], public_access_block: bool
) -> str:
    """The legacy toolkit stack, its staging bucket read through S3, and a write and read in it.

    Returns the bucket name.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    stack = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"legacy toolkit stack {toolkit!r} is {stack['StackStatus']!r}, expected 'CREATE_COMPLETE'"
    )
    assert _user_tags(stack.get("Tags", [])) == user_tags, (
        f"legacy toolkit stack tags are {stack.get('Tags')!r}, expected {user_tags!r}"
    )
    assert stack.get("Parameters", []) == [], (
        f"legacy toolkit stack has parameters {stack.get('Parameters')!r}, expected none"
    )
    resources = sorted(
        (r["LogicalResourceId"], r["ResourceType"], r["ResourceStatus"])
        for r in cfn.describe_stack_resources(StackName=toolkit)["StackResources"]
    )
    assert resources == [
        ("StagingBucket", "AWS::S3::Bucket", "CREATE_COMPLETE"),
        ("StagingBucketPolicy", "AWS::S3::BucketPolicy", "CREATE_COMPLETE"),
    ], f"legacy toolkit stack resources are {resources!r}"
    bucket = _legacy_bucket(ctx, toolkit)
    # With no BucketName, CloudFormation names the bucket <stack>-<logical id>-<suffix>, lowercased.
    generated = rf"{re.escape(toolkit.lower())}-stagingbucket-[a-z0-9]+"
    assert bucket and re.fullmatch(generated, bucket), (
        f"legacy staging bucket is named {bucket!r}, expected the generated "
        f"'{toolkit.lower()}-stagingbucket-<suffix>'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    _assert_bucket_domain(ctx, outputs.pop("BucketDomainName", ""), bucket)
    assert outputs == {"BucketName": bucket}, f"legacy toolkit stack outputs are {outputs!r}"
    template = _template_dict(
        cfn.get_template(StackName=toolkit, TemplateStage="Original")["TemplateBody"]
    )
    condition = template["Conditions"]["UsePublicAccessBlockConfiguration"]
    flag = "true" if public_access_block else "false"
    assert condition == {"Fn::Equals": [flag, "true"]}, (
        f"deployed template condition UsePublicAccessBlockConfiguration is {condition!r}, "
        f"expected {{'Fn::Equals': [{flag!r}, 'true']}}"
    )

    # S3's view of the bucket.
    rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    want_rules = [
        {
            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
            "BucketKeyEnabled": False,
        }
    ]
    # The template's settings only: S3 adds its own, such as the encryption types it blocks.
    keys = ("ApplyServerSideEncryptionByDefault", "BucketKeyEnabled")
    defaults = [{k: r.get(k) for k in keys} for r in rules]
    assert defaults == want_rules, (
        f"legacy staging bucket encryption rules are {rules!r}, expected {want_rules!r}"
    )
    # A new bucket blocks public access unless told otherwise; the false flag only omits the
    # property, so S3's default still applies.
    block = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    assert block == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }, f"legacy staging bucket public access block is {block!r}, expected all four True"
    versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert versioning is None, f"legacy staging bucket versioning is {versioning!r}, expected unset"
    policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    bucket_arn = f"arn:aws:s3:::{bucket}"
    got_statements = [
        (s.get("Sid"), s.get("Effect"), s.get("Principal"), s.get("Action"))
        + (sorted(s.get("Resource", [])), s.get("Condition"))
        for s in policy["Statement"]
    ]
    assert (policy.get("Id"), got_statements) == (
        "AccessControl",
        [
            (
                "AllowSSLRequestsOnly",
                "Deny",
                "*",
                "s3:*",
                [bucket_arn, f"{bucket_arn}/*"],
                {"Bool": {"aws:SecureTransport": "false"}},
            )
        ],
    ), f"legacy staging bucket policy is {policy!r}"
    assert _bucket_user_tags(ctx, bucket) == user_tags, (
        f"legacy staging bucket tags differ from {user_tags!r}"
    )

    # The bucket stores and serves an object, encrypted by its default.
    key, body = ctx.unique_name("probe/"), ctx.unique_name("marker-").encode()
    put = s3.put_object(Bucket=bucket, Key=key, Body=body)
    got = s3.get_object(Bucket=bucket, Key=key)
    stored = (got["Body"].read(), put.get("ServerSideEncryption"), got.get("ServerSideEncryption"))
    assert stored == (body, "aws:kms", "aws:kms"), (
        f"s3://{bucket}/{key} did not round-trip KMS-encrypted: {stored!r}"
    )
    return bucket


def _bucket_user_tags(ctx, bucket: str) -> list[tuple[str, str]]:
    """The bucket's tags without `aws:` keys; a bucket with no tag set has none."""
    try:
        return _user_tags(ctx.client("s3").get_bucket_tagging(Bucket=bucket)["TagSet"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchTagSet":
            return []
        raise


def _step_timeout(ctx, ceiling_s: float) -> float:
    """A step's timeout: *ceiling_s*, capped so the step ends before the runner stops the check."""
    left = ctx.time_left()
    return ceiling_s if left is None else max(1.0, min(ceiling_s, left - _RESERVE_S))


def _assert_bucket_domain(ctx, domain: str, bucket: str) -> None:
    """The BucketDomainName output names the bucket's regional S3 host, by its labels."""
    labels = f"{bucket}.s3.{ctx.region}."
    assert domain.startswith(labels), (
        f"toolkit output BucketDomainName is {domain!r}, expected the host {labels}<domain>"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
