"""get-property-value-history-nonexistent-entity-not-found."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-property-value-history-nonexistent-entity-not-found"
GROUP = "error-semantics"
SERVICES = ["iottwinmaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a real property returns 21.5, GetPropertyValueHistory on a missing entity fails
    ResourceNotFoundException and on a missing component fails ValidationException, each with the exact message."""
    tm = ctx.client("iottwinmaker")
    workspace_id, _role_arn, _bucket = _create_workspace(ctx)

    component_type_id = ctx.unique_name("sim2real.tm.sensor.")
    tm.create_component_type(
        workspaceId=workspace_id,
        componentTypeId=component_type_id,
        propertyDefinitions={"Temperature": {"dataType": {"type": "DOUBLE"}, "defaultValue": {"doubleValue": 21.5}}},
    )
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_component_type(workspaceId=workspace_id, componentTypeId=component_type_id)))
    _wait_component_type_state(ctx, workspace_id, component_type_id, {"ACTIVE", "ERROR"})

    real_entity_id = tm.create_entity(
        workspaceId=workspace_id,
        entityName=ctx.unique_name("sim2real-entity-"),
        components={"Sensor": {"componentTypeId": component_type_id}},
    )["entityId"]
    ctx.on_cleanup(lambda: _retry_teardown(lambda: tm.delete_entity(workspaceId=workspace_id, entityId=real_entity_id)))
    _wait_entity_state(ctx, workspace_id, real_entity_id, {"ACTIVE", "ERROR"})

    # positive control: the real entity/component/property is genuinely readable and returns
    # real data, so the rejections below cannot be explained by a broken read path in general.
    value_resp = tm.get_property_value(
        workspaceId=workspace_id, entityId=real_entity_id, componentName="Sensor", selectedProperties=["Temperature"]
    )
    got_value = value_resp["propertyValues"]["Temperature"]["propertyValue"]["doubleValue"]
    assert got_value == 21.5, f"unexpected value_resp={value_resp!r}"

    # a well-formed time range, so each refusal is about the bad reference, not the time window.
    now = datetime.now(timezone.utc)
    start_time = _iso_time(now - timedelta(days=1))
    end_time = _iso_time(now)

    bogus_entity_id = ctx.unique_name("sim2real-nonexistent-entity-")
    err = _client_error(
        lambda: tm.get_property_value_history(
            workspaceId=workspace_id,
            entityId=bogus_entity_id,
            componentName="Sensor",
            selectedProperties=["Temperature"],
            startTime=start_time,
            endTime=end_time,
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"unexpected error={err!r}"
    expected_message = f"Entity {bogus_entity_id} in workspace {workspace_id} not found."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    err2 = _client_error(
        lambda: tm.get_property_value_history(
            workspaceId=workspace_id,
            entityId=real_entity_id,
            componentName="NoSuchComponent",
            selectedProperties=["Temperature"],
            startTime=start_time,
            endTime=end_time,
        )
    )
    assert err2["Code"] == "ValidationException", f"unexpected error={err2!r}"
    expected_message2 = f"Component NoSuchComponent of Entity {real_entity_id} in workspace {workspace_id} not found."
    assert err2["Message"] == expected_message2, f"expected message {expected_message2!r}, got {err2['Message']!r}"


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
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_history(
    ctx, workspace_id, entity_id, component_name, property_name, start_time, end_time, expected_count, timeout_s=60.0
):
    tm = ctx.client("iottwinmaker")
    deadline = time.monotonic() + timeout_s
    last_values = []
    while time.monotonic() < deadline:
        resp = tm.get_property_value_history(
            workspaceId=workspace_id,
            entityId=entity_id,
            componentName=component_name,
            selectedProperties=[property_name],
            startTime=start_time,
            endTime=end_time,
            orderByTime="ASCENDING",
        )
        history = resp.get("propertyValues", [])
        last_values = history[0]["values"] if history else []
        if len(last_values) >= expected_count:
            return last_values
        time.sleep(2)
    raise AssertionError(f"expected {expected_count} history values, got {len(last_values)}")


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
