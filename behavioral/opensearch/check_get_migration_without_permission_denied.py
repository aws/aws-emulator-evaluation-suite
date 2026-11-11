"""get-migration-without-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-migration-without-permission-denied"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An explicit Deny on GetMigration yields AccessDeniedException with the exact message, the
    same role's allowed ListMigrations is not AccessDenied, and an authorized caller gets not-found.
    """
    aos = ctx.client("opensearch")
    app_id = _create_application(ctx, aos)
    fake_migration_id = ctx.unique_name("sim2real-mig-")

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "es:GetMigration", "Resource": "*"},
            {"Effect": "Allow", "Action": "es:ListMigrations", "Resource": "*"},
        ],
    }
    restricted, principal_arn = _assume_role_client(ctx, "opensearch", deny_policy)

    code, message = _error(lambda: restricted.get_migration(migrationId=fake_migration_id))
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    expected = (
        f"User: {principal_arn} is not authorized to perform: es:GetMigration on resource: "
        f"arn:aws:opensearch:{ctx.region}:{ctx.account}:application/* "
        "with an explicit deny in an identity-based policy"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # ListMigrations on an application another principal created returns
    # ResourceNotFoundException for this role (per-principal visibility), so only "not
    # AccessDenied" is asserted.
    try:
        restricted.list_migrations(applicationId=app_id)
        list_code = None
    except ClientError as exc:
        list_code = exc.response["Error"]["Code"]
    assert list_code != "AccessDeniedException", (
        f"ListMigrations is explicitly Allowed for this role, so its rejection must not "
        f"be AccessDeniedException; got {list_code}"
    )

    # Positive control: an authorized caller gets ResourceNotFoundException for the same id.
    control_code, control_message = _error(lambda: aos.get_migration(migrationId=fake_migration_id))
    assert control_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {control_code}"
    # The service reads the id's leading segment as the owning application id.
    expected = f"Application {fake_migration_id.split('-')[0]} not found"
    assert control_message == expected, f"expected message {expected!r}, got {control_message!r}"


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_application(id=app_id)))
    return app_id


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _assume_role_client(ctx, service_name: str, policy_document: dict):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-behav-role-")[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = ctx.unique_name("sim2real-behav-policy-")[:64]
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    session_name = "sim2real-behav-session"
    deadline = time.monotonic() + 60.0
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except Exception as exc:
            last_err = exc
            time.sleep(3)
    if creds is None:
        raise AssertionError(f"could not assume role {role_arn} within 60s: {last_err}")

    client = ctx.client(
        service_name,
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    principal_arn = f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"
    return client, principal_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
