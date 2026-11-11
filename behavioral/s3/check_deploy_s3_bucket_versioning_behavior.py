"""deploy-s3-bucket-versioning-behavior."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-s3-bucket-versioning-behavior"
GROUP = "deploy"
SERVICES = ["s3"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
      Tags:
        - Key: sim2real
          Value: deploy-s3-bucket-versioning-behavior
Outputs:
  BucketName:
    Value: !Ref Bucket
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed bucket with VersioningConfiguration Enabled produces multiple
    retrievable object versions on repeated PutObject, not merely a successful stack."""
    stack_name = ctx.unique_name("sim2real-s3-vers-")
    outputs = _deploy_stack(ctx, stack_name, _TEMPLATE)
    bucket = outputs["BucketName"]

    s3 = ctx.client("s3")

    # The stack claims versioning is enabled -- confirm the control-plane read agrees.
    versioning = s3.get_bucket_versioning(Bucket=bucket)
    assert versioning.get("Status") == "Enabled", (
        f"expected bucket versioning Status 'Enabled', got {versioning.get('Status')!r}"
    )

    key = "versioned-object.txt"
    put1 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-one")
    put2 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-two-longer-body")
    version_id_1 = put1["VersionId"]
    version_id_2 = put2["VersionId"]
    assert version_id_1 != version_id_2, (
        f"two PutObject calls on the same key returned the same VersionId {version_id_1!r}"
    )

    listing = s3.list_object_versions(Bucket=bucket, Prefix=key)
    versions = [v for v in listing.get("Versions", []) if v["Key"] == key]
    assert len(versions) == 2, f"expected 2 retrievable versions, got {len(versions)}"
    seen_ids = {v["VersionId"] for v in versions}
    assert seen_ids == {version_id_1, version_id_2}, (
        f"expected ListObjectVersions to report {{version_id_1, version_id_2}}, got {seen_ids}"
    )

    latest = [v for v in versions if v["IsLatest"]]
    assert len(latest) == 1, f"expected exactly 1 version flagged IsLatest, got {len(latest)}"
    assert latest[0]["VersionId"] == version_id_2, (
        f"expected the latest version to be {version_id_2!r}, got {latest[0]['VersionId']!r}"
    )

    # Both versions must actually be independently retrievable with distinct content.
    body_old = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id_1)["Body"].read()
    body_new = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id_2)["Body"].read()
    assert body_old == b"version-one", f"expected body b'version-one' for {version_id_1!r}, got {body_old!r}"
    assert body_new == b"version-two-longer-body", (
        f"expected body b'version-two-longer-body' for {version_id_2!r}, got {body_new!r}"
    )


def _deploy_stack(ctx: Any, stack_name: str, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
    ctx.on_cleanup(lambda: _teardown_stack(ctx, stack_name, outputs))
    return outputs


def _teardown_stack(ctx: Any, stack_name: str, outputs: dict) -> None:
    bucket = outputs.get("BucketName")
    if bucket:
        try:
            _empty_bucket(ctx, bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _empty_bucket(ctx: Any, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objects = []
        for v in page.get("Versions", []):
            objects.append({"Key": v["Key"], "VersionId": v["VersionId"]})
        for m in page.get("DeleteMarkers", []):
            objects.append({"Key": m["Key"], "VersionId": m["VersionId"]})
        if objects:
            for i in range(0, len(objects), 1000):
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects[i:i + 1000]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
