"""access-denied-precedes-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "access-denied-precedes-not-found"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMigration and DescribeDataSourceAttachment check permissions before existence: an
    unpermissioned caller gets AccessDeniedException for a nonexistent target that an authorized
    caller sees as ResourceNotFoundException, with the exact messages asserted."""
    aos = ctx.client("opensearch")
    app_id = _create_application(ctx, aos)

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_migration_id = ctx.unique_name("sim2real-mig-")
    bogus_domain = ctx.unique_name("sim2real-adnf-").lower().replace("_", "-")[:28]
    fake_ds_arn = f"arn:aws:es:{ctx.region}:{account_id}:domain/{bogus_domain}"

    restricted, caller_arn = _assume_role_client(ctx, "opensearch", policy_document=None)

    code_get, msg_get = _client_error(lambda: restricted.get_migration(migrationId=fake_migration_id))
    assert code_get == "AccessDeniedException", f"expected AccessDeniedException, got {code_get}"
    expected = (
        f"User: {caller_arn} is not authorized to perform: es:GetMigration on resource: "
        f"arn:aws:opensearch:{ctx.region}:{account_id}:application/* "
        "because no identity-based policy allows the es:GetMigration action"
    )
    assert msg_get == expected, f"GetMigration denial message: expected {expected!r}, got {msg_get!r}"

    code_desc, msg_desc = _client_error(
        lambda: restricted.describe_data_source_attachment(id=app_id, dataSourceArn=fake_ds_arn)
    )
    assert code_desc == "AccessDeniedException", f"expected AccessDeniedException, got {code_desc}"
    expected = (
        f"User: {caller_arn} is not authorized to perform: es:DescribeDataSourceAttachment on "
        f"resource: arn:aws:es:{ctx.region}:{account_id}:domain/* "
        "because no identity-based policy allows the es:DescribeDataSourceAttachment action"
    )
    assert msg_desc == expected, (
        f"DescribeDataSourceAttachment denial message: expected {expected!r}, got {msg_desc!r}"
    )

    # Control: the same targets under the authorized client are not-found, so the denial
    # above is a permission check rather than a malformed target.
    control_get_code, control_get_msg = _client_error(
        lambda: aos.get_migration(migrationId=fake_migration_id)
    )
    assert control_get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {control_get_code}"
    )
    # GetMigration names the id's text before its first '-' as the missing application.
    expected = f"Application {fake_migration_id.split('-', 1)[0]} not found"
    assert control_get_msg == expected, (
        f"GetMigration not-found message: expected {expected!r}, got {control_get_msg!r}"
    )

    control_desc_code, control_desc_msg = _client_error(
        lambda: aos.describe_data_source_attachment(id=app_id, dataSourceArn=fake_ds_arn)
    )
    assert control_desc_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {control_desc_code}"
    )
    expected = (
        f"Data source attachment not found for application {app_id} and data source {fake_ds_arn}"
    )
    assert control_desc_msg == expected, (
        f"DescribeDataSourceAttachment not-found message: expected {expected!r}, got {control_desc_msg!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_application(ctx, aos) -> str:
    raw = ctx.unique_name("sim2real-app-").lower()
    name = "".join(c for c in raw if c.isalnum() or c == "-")[:30].rstrip("-")
    if not name or not name[0].isalpha():
        name = "a" + name
    resp = aos.create_application(name=name[:30], tagList=[{"Key": "sim2real", "Value": CHECK}])
    app_id = resp["id"]
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_application(id=app_id)))
    return app_id


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _assume_role_client(ctx, service_name: str, policy_document: dict | None):
    """Create and assume a role with only the optional inline policy; return a `service_name`
    client signing as it and the assumed-role session ARN."""
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

    if policy_document is not None:
        policy_name = ctx.unique_name("sim2real-behav-policy-")[:64]
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
        )
        ctx.on_cleanup(
            lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
        )

    session_name = "sim2real-behav-session"
    deadline = time.monotonic() + 60.0
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
            break
        except Exception as exc:  # role/policy propagation delay
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
    return client, f"arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
