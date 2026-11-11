"""cfn-package-large-template-uploads-to-s3-positive."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.parse

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cfn-package-large-template-uploads-to-s3-positive"
GROUP = "resource-binding"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws cloudformation package` uploads a nested template over the 51,200-byte TemplateBody limit
    as exactly one object in the given S3 bucket, whose content equals the original, and rewrites
    the parent's TemplateURL to the URL of that object."""
    require_tools("aws")

    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cfnpkg-")
    _create_bucket(ctx, s3, bucket)

    tmpdir = tempfile.mkdtemp(prefix="cfnpkg-")
    ctx.on_cleanup(lambda: shutil.rmtree(tmpdir, ignore_errors=True))

    # Nested template padded well past CloudFormation's 51,200-byte inline TemplateBody limit
    # (see "Size limitation" in the CloudFormation user guide).
    nested_doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Metadata": {"Filler": "x" * 60000},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }
    nested_path = os.path.join(tmpdir, "nested.json")
    with open(nested_path, "w") as f:
        json.dump(nested_doc, f)
    nested_size = os.path.getsize(nested_path)
    assert nested_size > 51200, f"nested template only {nested_size} bytes, need >51200"

    root_doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Nested": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {"TemplateURL": "./nested.json"},
            }
        },
    }
    root_path = os.path.join(tmpdir, "root.json")
    with open(root_path, "w") as f:
        json.dump(root_doc, f)

    packaged_path = os.path.join(tmpdir, "packaged.json")
    _run_shell(
        ctx,
        [
            "aws", "cloudformation", "package",
            "--template-file", root_path,
            "--s3-bucket", bucket,
            "--use-json",
            "--output-template-file", packaged_path,
        ],
    )

    with open(packaged_path) as f:
        packaged_doc = json.load(f)
    template_url = packaged_doc["Resources"]["Nested"]["Properties"]["TemplateURL"]

    # Discover the uploaded object directly (the bucket was created solely for this check,
    # so the single object present after `package` is the one it uploaded).
    listing = s3.list_objects_v2(Bucket=bucket)
    contents = listing.get("Contents", [])
    assert len(contents) == 1, f"expected exactly one uploaded object, found {len(contents)}"
    key = contents[0]["Key"]
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    # The CLI writes a path-style URL on the S3 endpoint it was given, so the bucket and key in
    # its output are what the target decides.
    parsed = urllib.parse.urlparse(template_url)
    assert parsed.path == f"/{bucket}/{key}", (
        f"packaged TemplateURL {template_url!r} does not name the uploaded object {bucket}/{key}"
    )

    obj = s3.get_object(Bucket=bucket, Key=key)
    uploaded_body = obj["Body"].read()
    with open(nested_path, "rb") as f:
        original_body = f.read()
    # `package` re-serializes the nested template while uploading it (it also recursively
    # packages anything referenced *inside* that template, and may wrap the artifact in a
    # zip archive), so compare parsed JSON content rather than raw bytes -- formatting
    # (whitespace/key order) is allowed to differ, and unwrap a zip if present.
    uploaded_doc = _parse_template_bytes(uploaded_body)
    assert uploaded_doc == json.loads(original_body), (
        "uploaded S3 object content does not match source nested template"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    """Run a shell command (str -> shell=True, or argv list) with the target's credentials and region in the
    env (via ctx.subprocess_env). Raises on non-zero exit when check=True. Returns CompletedProcess."""
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs = {"Bucket": name}
    # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every other
    # region requires it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK},
        {"Key": "sim2real:managed", "Value": "true"},
    ]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=name)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _parse_template_bytes(body: bytes):
    """`package` may upload the packaged nested-stack artifact as a YAML re-serialization of
    the template regardless of the root template's `--use-json` flag (that flag only governs
    the on-disk format of the *root* `--output-template-file`), or, for some artifact types,
    as a zip archive containing a single template file. Parse whichever shape is present and
    return the decoded template as a dict."""
    import io
    import zipfile

    if body[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(body)) as zf:
            names = zf.namelist()
            assert len(names) == 1, f"expected a single member in packaged zip, found {names}"
            body = zf.read(names[0])
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        import yaml

        return yaml.safe_load(body)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
