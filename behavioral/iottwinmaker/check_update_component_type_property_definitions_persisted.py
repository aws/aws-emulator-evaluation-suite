"""update-component-type-property-definitions-persisted."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-component-type-property-definitions-persisted"
GROUP = "state-machine"
SERVICES = ["iottwinmaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateComponentType replaces the property set: after it settles ACTIVE, the new Humidity property is a
    DOUBLE and the omitted Pressure property is gone."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    component_type_id = ctx.unique_name("sim2real.tm.device.")
    tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=component_type_id,
        propertyDefinitions={"Pressure": {"dataType": {"type": "DOUBLE"}}},
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id))
    created = _wait_component_type_state(ctx, workspace_id, component_type_id, {"ACTIVE", "ERROR"})
    assert "Pressure" in created["propertyDefinitions"], f"expected Pressure in initial propertyDefinitions, got {created['propertyDefinitions']}"

    update_resp = tm.update_component_type(
        workspaceId=workspace_id,
        componentTypeId=component_type_id,
        propertyDefinitions={"Humidity": {"dataType": {"type": "DOUBLE"}}},
    )
    assert update_resp["state"] in ("UPDATING", "ACTIVE"), f"expected UpdateComponentType state in (UPDATING, ACTIVE), got {update_resp['state']}"

    final = _wait_component_type_state(ctx, workspace_id, component_type_id, {"ACTIVE", "ERROR"})
    assert final["status"]["state"] == "ACTIVE", final["status"]
    assert "Humidity" in final["propertyDefinitions"], f"expected Humidity in updated propertyDefinitions, got {final['propertyDefinitions']}"
    assert final["propertyDefinitions"]["Humidity"]["dataType"]["type"] == "DOUBLE", final["propertyDefinitions"]["Humidity"]
    # replace semantics: a property omitted from the UpdateComponentType request does not survive.
    assert "Pressure" not in final["propertyDefinitions"], final["propertyDefinitions"]


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
    # us-east-1 is the one region S3 rejects a LocationConstraint for; every other region needs it.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]},
    )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
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
                tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
