"""component-type-create-reaches-active-state."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "component-type-create-reaches-active-state"
GROUP = "state-machine"
SERVICES = ["iottwinmaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateComponentType reaches ACTIVE with a DOUBLE time-series Temperature property; after delete, a read and
    an update both fail ResourceNotFoundException with the exact message."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    component_type_id = ctx.unique_name("sim2real.tm.sensor.")
    create_resp = tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=component_type_id,
        propertyDefinitions={
            "Temperature": {
                "dataType": {"type": "DOUBLE"},
                "isTimeSeries": True,
                "isStoredExternally": True,
            }
        },
        tags=_mgmt_tags(),
    )
    ctx.on_cleanup(lambda: _delete_component_type(ctx, workspace_id, component_type_id))
    assert create_resp["state"] in ("CREATING", "ACTIVE"), (
        f"expected CreateComponentType state in (CREATING, ACTIVE), got {create_resp['state']!r}"
    )

    final = _wait_component_type_state(ctx, workspace_id, component_type_id, {"ACTIVE", "ERROR"})
    assert final["status"]["state"] == "ACTIVE", final["status"]
    assert "Temperature" in final["propertyDefinitions"], final["propertyDefinitions"]
    assert final["propertyDefinitions"]["Temperature"]["dataType"]["type"] == "DOUBLE", (
        f"expected dataType DOUBLE, got {final['propertyDefinitions']['Temperature']['dataType']}"
    )
    assert final["propertyDefinitions"]["Temperature"]["isTimeSeries"] is True, (
        f"expected isTimeSeries True, got {final['propertyDefinitions']['Temperature'].get('isTimeSeries')}"
    )

    tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
    _wait_component_type_removed(ctx, workspace_id, component_type_id)
    not_found_code, not_found_message = _error(
        lambda: tm.get_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected a deleted component type read to be ResourceNotFoundException, got {not_found_code}"
    )
    expected = f"Cannot find component type {component_type_id} in workspace {workspace_id}."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"
    mutate_code, mutate_message = _error(
        lambda: tm.update_component_type(
            workspaceId=workspace_id,
            componentTypeId=component_type_id,
            propertyDefinitions={"Pressure": {"dataType": {"type": "DOUBLE"}}},
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected UpdateComponentType on a deleted component type to be ResourceNotFoundException, got {mutate_code}"
    )
    expected = f"Cannot find component type {component_type_id} in workspace {workspace_id}."
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-tm"}


def _error(fn):
    try:
        fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


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


def _delete_component_type(ctx, workspace_id, component_type_id):
    tm = ctx.client("iottwinmaker")
    try:
        tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # DeleteComponentType is asynchronous and AWS refuses DeleteWorkspace while the type remains.
    _wait_component_type_removed(ctx, workspace_id, component_type_id)


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
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in _mgmt_tags().items()]}
    )
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
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
                tags=_mgmt_tags(),
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
    ctx.on_cleanup(lambda: tm.delete_workspace(workspaceId=workspace_id))
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


def _wait_component_type_removed(ctx, workspace_id, component_type_id, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            tm.get_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError("component type was never fully removed")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
