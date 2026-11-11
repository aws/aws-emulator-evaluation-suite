"""get-schema-mapping-access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-schema-mapping-access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["entityresolution"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role with no entityresolution permissions gets AccessDeniedException and its exact message from
    GetSchemaMapping while the permitted caller reads the mapping; granting the role that one action then
    lets the same call return the mapping."""
    er = ctx.client("entityresolution")
    schema_name = ctx.unique_name("sim2real-er-authz-")
    created = er.create_schema_mapping(
        schemaName=schema_name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, schema_name))
    schema_arn = created["schemaArn"]

    # Positive control: a fully-permitted caller can read the mapping before anything is denied.
    control = er.get_schema_mapping(schemaName=schema_name)
    assert control["schemaName"] == schema_name, (
        f"positive control failed: expected schemaName {schema_name!r}, got {control.get('schemaName')!r}"
    )

    unprivileged_client, role_name = _assume_unprivileged_client(ctx)

    denied, denied_message = _error_code(
        lambda: unprivileged_client.get_schema_mapping(schemaName=schema_name)
    )
    assert denied == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no entityresolution permissions, "
        f"got {denied!r}"
    )
    account = schema_arn.split(":")[4]
    expected_message = (
        f"User: arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION_NAME} is not "
        f"authorized to perform: entityresolution:GetSchemaMapping on resource: {schema_arn} "
        "because no identity-based policy allows the entityresolution:GetSchemaMapping action"
    )
    assert denied_message == expected_message, (
        f"expected the denial {expected_message!r}, got {denied_message!r}"
    )

    # Restore: grant exactly the missing action to the SAME role and demand the identical call
    # now succeeds, so the denial above is shown to be governed by the policy, not something else.
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-er-allow-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "entityresolution:GetSchemaMapping",
                    "Resource": schema_arn,
                }
            ],
        }),
    )
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name, policy_name))

    restored = _poll_until(
        lambda: _error_code_or_result(lambda: unprivileged_client.get_schema_mapping(schemaName=schema_name)),
        lambda r: r[0] == "success",
        # IAM propagation of an inline-policy grant can exceed a minute on real AWS.
        timeout_s=_propagation_budget(ctx, 300.0),
        interval_s=2.0,
        description="the granted permission takes effect for the same assumed-role session",
    )
    result = restored[1]
    assert result["schemaName"] == schema_name, (
        f"after granting entityresolution:GetSchemaMapping, expected schemaName {schema_name!r}, "
        f"got {result.get('schemaName')!r}"
    )


_SESSION_NAME = "sim2real-noperm"


def _propagation_budget(ctx, cap_s):
    """cap_s, bounded by the run's remaining time less 10 s so the poll fails with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 10.0))


def _assume_unprivileged_client(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-er-noperm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    role_arn = role["Role"]["Arn"]

    deadline = time.monotonic() + 60.0
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            break
        except ClientError as e:
            last_err = e
            time.sleep(3)
    if creds is None:
        raise AssertionError(f"could not assume the no-permissions role in time: {last_err}")

    client = ctx.client(
        "entityresolution",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_name


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _error_code_or_result(fn):
    """("success", result) or ("error", (code, message)) -- never a sentinel that a real error code equals."""
    try:
        return ("success", fn())
    except ClientError as e:
        return ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message", "")))


def _error_code(fn):
    """Call fn(); return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _safe_delete_schema(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
