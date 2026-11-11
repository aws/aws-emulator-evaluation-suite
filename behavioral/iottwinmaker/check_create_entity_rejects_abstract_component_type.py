"""create-entity-rejects-abstract-component-type."""
from __future__ import annotations

import json
import time

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-entity-rejects-abstract-component-type"
GROUP = "overly-permissive"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEntity with a component type whose only property is stored externally without a data connector fails
    ValidationException with the exact message and creates no entity, while a concrete component type is accepted."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    component_type_id = ctx.unique_name("sim2real.tm.sensor.")
    tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=component_type_id,
        propertyDefinitions={
            "Temperature": {"dataType": {"type": "DOUBLE"}, "isTimeSeries": True, "isStoredExternally": True}
        },
    )
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)))
    _wait_component_type_state(ctx, workspace_id, component_type_id, {"ACTIVE", "ERROR"})

    concrete_component_type_id = ctx.unique_name("sim2real.tm.label.")
    tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=concrete_component_type_id,
        propertyDefinitions={"Label": {"dataType": {"type": "STRING"}}},
    )
    ctx.on_cleanup(
        lambda: _retry_teardown(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=concrete_component_type_id))
    )
    _wait_component_type_state(ctx, workspace_id, concrete_component_type_id, {"ACTIVE", "ERROR"})

    entity_name = ctx.unique_name("sim2real-entity-")
    err = _client_error(
        lambda: tm.create_entity(
            workspaceId=workspace_id,
            entityName=entity_name,
            components={"Sensor": {"componentTypeId": component_type_id}},
        )
    )
    assert err["Code"] == "ValidationException", f"unexpected error={err!r}"
    expected_message = f"Abstract ComponentType {component_type_id} can not be used for creating a component"
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # effect absent: no entity with this name/id was left behind by the rejected call.
    listed_names = {
        summary["entityName"] for summary in tm.list_entities(workspaceId=workspace_id)["entitySummaries"]
    }
    assert entity_name not in listed_names

    # positive control, same shape: a concrete (non-abstract) component type on a real entity is
    # accepted -- proving the rejection above is about abstractness, not about having any
    # component type at all.
    concrete_entity_name = ctx.unique_name("sim2real-concrete-")
    concrete_entity_id = tm.create_entity(
        workspaceId=workspace_id,
        entityName=concrete_entity_name,
        components={"Labelled": {"componentTypeId": concrete_component_type_id}},
    )["entityId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=concrete_entity_id)))
    _wait_entity_state(ctx, workspace_id, concrete_entity_id, {"ACTIVE", "ERROR"})
    listed_names_after_concrete = {
        summary["entityName"] for summary in tm.list_entities(workspaceId=workspace_id)["entitySummaries"]
    }
    assert concrete_entity_name in listed_names_after_concrete

    # positive control: an entity with no components at all is created successfully.
    plain_entity_id = tm.create_entity(workspaceId=workspace_id, entityName=ctx.unique_name("sim2real-plain-"))[
        "entityId"
    ]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=plain_entity_id)))
    _wait_entity_state(ctx, workspace_id, plain_entity_id, {"ACTIVE", "ERROR"})


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


def _iso_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


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
    role_name = ctx.unique_name("sim2real-tm-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
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
            tm.create_workspace(workspaceId=workspace_id, s3Location=f"arn:aws:s3:::{bucket_name}", role=role_arn)
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
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_entity_state(ctx, workspace_id, entity_id, target_states, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last = None
    resp = None
    while time.monotonic() < deadline:
        resp = tm.get_entity(workspaceId=workspace_id, entityId=entity_id)
        last = resp.get("status", {}).get("state")
        if last in target_states:
            return resp
        time.sleep(2)
    raise AssertionError(f"entity never reached {target_states}, last state={last}, resp={resp}")


def _poll_property_value(ctx, workspace_id, entity_id, component_name, property_name, timeout_s=60.0):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = tm.get_property_value(
            workspaceId=workspace_id,
            entityId=entity_id,
            componentName=component_name,
            selectedProperties=[property_name],
        )
        latest = resp.get("propertyValues", {}).get(property_name)
        if latest is not None:
            return latest["propertyValue"]["doubleValue"]
        time.sleep(2)
    raise AssertionError(f"property value for {property_name} never appeared")


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
