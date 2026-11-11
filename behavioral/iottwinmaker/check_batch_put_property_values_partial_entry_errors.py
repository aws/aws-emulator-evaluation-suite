"""batch-put-property-values-partial-entry-errors."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "batch-put-property-values-partial-entry-errors"
GROUP = "data-plane"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchPutPropertyValues fails the whole call instead of returning errorEntries: a property without a
    connector fails ValidationException naming the connector, a missing component and a mixed batch fail with
    the exact component message, and a missing entity fails ResourceNotFoundException with the exact message."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    component_type_id = ctx.unique_name("sim2real.tm.sensor.")
    tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=component_type_id,
        propertyDefinitions={"Status": {"dataType": {"type": "STRING"}, "defaultValue": {"stringValue": "OK"}}},
    )
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)))
    _wait_component_type_state(ctx, workspace_id, component_type_id, {"ACTIVE", "ERROR"})

    entity_id = tm.create_entity(
        workspaceId=workspace_id,
        entityName=ctx.unique_name("sim2real-entity-"),
        components={"Sensor": {"componentTypeId": component_type_id}},
    )["entityId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=entity_id)))
    _wait_entity_state(ctx, workspace_id, entity_id, {"ACTIVE", "ERROR"})

    def _entry(component_name):
        return {
            "entityPropertyReference": {
                "entityId": entity_id,
                "componentName": component_name,
                "propertyName": "Status",
            },
            "propertyValues": [
                {"value": {"stringValue": "updated"}, "time": _iso_time(datetime.now(timezone.utc))}
            ],
        }

    # control: a fully well-formed reference (real entity, real ACTIVE component, real property)
    # is still rejected, but with a connector-specific ValidationException message -- proving the
    # rejection below is about the missing component, not about every BatchPutPropertyValues call
    # failing identically regardless of what it references.
    real_ref_error = _client_error(lambda: tm.batch_put_property_values(workspaceId=workspace_id, entries=[_entry("Sensor")]))
    assert real_ref_error["Code"] == "ValidationException", f"unexpected error={real_ref_error!r}"
    # message varies: AWS echoes its internal connector request, including a server-generated
    # entryId, so its stable part (it names the connector) and its distinctness from the
    # component-lookup message below are asserted.
    bad_component_message = f"Component NoSuchComponent of Entity {entity_id} in workspace {workspace_id} not found."
    assert "connector" in real_ref_error["Message"].lower(), (
        f"expected a connector-specific message, got {real_ref_error!r}"
    )
    assert real_ref_error["Message"] != bad_component_message, (
        f"expected a connector-specific message, got the component-lookup one: {real_ref_error!r}"
    )

    # negative: a component that does not exist on the entity at all is rejected with the same
    # error CODE but a distinct, component-lookup message -- never the connector one above.
    bad_component_error = _client_error(
        lambda: tm.batch_put_property_values(workspaceId=workspace_id, entries=[_entry("NoSuchComponent")])
    )
    assert bad_component_error["Code"] == "ValidationException", f"unexpected error={bad_component_error!r}"
    assert bad_component_error["Message"] == bad_component_message, (
        f"expected message {bad_component_message!r}, got {bad_component_error['Message']!r}"
    )

    # negative: a batch mixing the two entries above (each invalid for a different reason) is
    # rejected as a single HTTP-level failure -- never a 200 with a per-entry errorEntries list.
    mixed_error = _client_error(
        lambda: tm.batch_put_property_values(workspaceId=workspace_id, entries=[_entry("Sensor"), _entry("NoSuchComponent")])
    )
    assert mixed_error["Code"] == "ValidationException", f"unexpected error={mixed_error!r}"
    assert mixed_error["Message"] == bad_component_message, (
        f"expected message {bad_component_message!r}, got {mixed_error['Message']!r}"
    )

    bogus_entity_id = "sim2real-nonexistent-entity-does-not-exist"
    bad_entity_error = _client_error(
        lambda: tm.batch_put_property_values(
            workspaceId=workspace_id,
            entries=[
                {
                    "entityPropertyReference": {
                        "entityId": bogus_entity_id,
                        "componentName": "Sensor",
                        "propertyName": "Status",
                    },
                    "propertyValues": [
                        {"value": {"stringValue": "x"}, "time": _iso_time(datetime.now(timezone.utc))}
                    ],
                }
            ],
        )
    )
    assert bad_entity_error["Code"] == "ResourceNotFoundException", f"unexpected error={bad_entity_error!r}"
    bad_entity_message = f"Entity {bogus_entity_id} in workspace {workspace_id} not found."
    assert bad_entity_error["Message"] == bad_entity_message, (
        f"expected message {bad_entity_message!r}, got {bad_entity_error['Message']!r}"
    )


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
    deadline = time.monotonic() + 90
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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
