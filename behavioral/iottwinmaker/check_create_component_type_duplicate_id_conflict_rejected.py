"""create-component-type-duplicate-id-conflict-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-component-type-duplicate-id-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateComponentType with a componentTypeId that already exists in the workspace is rejected
    with ConflictException and the original definition is left untouched; a different, unused
    componentTypeId still creates successfully in the same workspace."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    component_type_id = ctx.unique_name("sim2real.tm.dup.")
    tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=component_type_id,
        propertyDefinitions={"Pressure": {"dataType": {"type": "DOUBLE"}}},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)))
    _wait_component_type_state(ctx, workspace_id, component_type_id, {"ACTIVE", "ERROR"})

    err = _client_error(
        lambda: tm.create_component_type(
            workspaceId=workspace_id,
            componentTypeId=component_type_id,
            propertyDefinitions={"Humidity": {"dataType": {"type": "DOUBLE"}}},
        )
    )
    assert err["Code"] == "ConflictException", f"expected ConflictException for a duplicate componentTypeId, got {err!r}"
    expected_message = f"Component type {component_type_id} in workspace {workspace_id} already exists."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # effect absent: original definition unchanged, the "Humidity" property from the rejected
    # duplicate call was never merged in.
    unchanged = tm.get_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
    assert "Pressure" in unchanged["propertyDefinitions"], unchanged["propertyDefinitions"]
    assert "Humidity" not in unchanged["propertyDefinitions"], unchanged["propertyDefinitions"]

    # positive control: a different componentTypeId in the same workspace still creates fine, and
    # the terminal read is independent of the CreateComponentType response that could merely echo
    # the request back.
    other_component_type_id = ctx.unique_name("sim2real.tm.other.")
    other_create = tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=other_component_type_id,
        propertyDefinitions={"Humidity": {"dataType": {"type": "DOUBLE"}}},
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(
        lambda: _retry_teardown(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=other_component_type_id))
    )
    assert other_create["state"] in ("CREATING", "ACTIVE"), other_create

    other_final = _wait_component_type_state(ctx, workspace_id, other_component_type_id, {"ACTIVE", "ERROR"})
    assert other_final["status"]["state"] == "ACTIVE", other_final["status"]
    assert "Humidity" in other_final["propertyDefinitions"], other_final["propertyDefinitions"]
    assert "Pressure" not in other_final["propertyDefinitions"], other_final["propertyDefinitions"]


_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iottwinmaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _s3_policy_document(bucket_name):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetBucket*", "s3:GetObject", "s3:ListBucket", "s3:PutObject", "s3:DeleteObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                }
            ],
        }
    )


def _delete_bucket(ctx, bucket_name):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket_name).get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_workspace_role(ctx):
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-tm-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="s3access", PolicyDocument=_s3_policy_document(bucket_name))
    return role_arn, bucket_name


def _create_workspace(ctx):
    tm = ctx.client("iottwinmaker")
    role_arn, bucket_name = _create_workspace_role(ctx)
    workspace_id = ctx.unique_name("sim2real-tm-ws-")
    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            tm.create_workspace(
                workspaceId=workspace_id,
                s3Location=f"arn:aws:s3:::{bucket_name}",
                role=role_arn,
                tags={"sim2real-check": CHECK},
            )
            break
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(3)
                continue
            raise
    else:
        raise AssertionError(f"CreateWorkspace never succeeded (IAM propagation?): {last_exc}")
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_workspace(workspaceId=workspace_id)))
    return workspace_id, role_arn, bucket_name


def _wait_component_type_state(ctx, workspace_id, component_type_id, target_states, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last = None
    resp = None
    while time.monotonic() < deadline:
        resp = tm.get_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
        last = resp.get("status", {}).get("state")
        if last in target_states:
            return resp
        time.sleep(2)
    raise AssertionError(f"component type never reached {target_states}, last state={last}, resp={resp}")


def _client_error(fn):
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the duplicate CreateComponentType to be rejected, but it succeeded: {result!r}")


def _retry_teardown(fn, timeout_s=180.0):
    """Teardown: retry a delete that AWS refuses while dependent resources are still being
    removed, and tolerate a resource that is already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ValidationException", "ConflictException") or time.monotonic() > deadline:
                raise
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
