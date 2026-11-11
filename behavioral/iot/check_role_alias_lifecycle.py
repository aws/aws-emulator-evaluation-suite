"""role-alias-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-alias-lifecycle"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoleAlias -> DescribeRoleAlias -> DeleteRoleAlias removes the alias such
    that subsequent lookups return ResourceNotFoundException."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")

    role_arn = _create_credentials_role(ctx, iam)

    alias = ctx.unique_name("sim2real-role-alias-")
    # IAM role trust policies are eventually consistent; IoT rejects the role
    # with InvalidRequestException until the role is visible to it, so retry
    # bounded rather than sleeping a fixed duration.
    created = _retry_while(
        lambda: iot.create_role_alias(
            roleAlias=alias,
            roleArn=role_arn,
            credentialDurationSeconds=3600,
            tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ),
        retry_codes={"InvalidRequestException"},
        timeout_s=20.0,
    )
    ctx.on_cleanup(lambda: _delete_role_alias_quiet(iot, alias))
    assert created["roleAlias"] == alias, f"expected CreateRoleAlias to echo roleAlias={alias!r}, got {created['roleAlias']!r}"

    described = iot.describe_role_alias(roleAlias=alias)["roleAliasDescription"]
    assert described["roleAlias"] == alias, f"expected DescribeRoleAlias roleAlias={alias!r}, got {described['roleAlias']!r}"
    assert described["roleArn"] == role_arn, f"expected DescribeRoleAlias roleArn={role_arn!r}, got {described['roleArn']!r}"
    assert described["credentialDurationSeconds"] == 3600, (
        f"expected DescribeRoleAlias credentialDurationSeconds=3600, got {described['credentialDurationSeconds']!r}"
    )

    iot.delete_role_alias(roleAlias=alias)

    code, code_message = _error(lambda: iot.describe_role_alias(roleAlias=alias))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeRoleAlias on a deleted alias to report ResourceNotFoundException, got {code!r}"
    )
    assert code_message == f"Role alias {alias} not found", (
        f"expected the exact {code} message, got {code_message!r}"
    )

    # A mutation on the dead id must also fail -- not just a read.
    update_code, update_code_message = _error(lambda: iot.update_role_alias(roleAlias=alias, credentialDurationSeconds=1800))
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateRoleAlias on a deleted alias to report ResourceNotFoundException, got {update_code!r}"
    )
    assert update_code_message == f"Role alias {alias} not found", (
        f"expected the exact {update_code} message, got {update_code_message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_while(fn, retry_codes, timeout_s=20.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_credentials_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-iot-alias-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "credentials.iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_quiet(iam, role_name))
    return role["Arn"]


def _delete_role_quiet(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_alias_quiet(iot, alias):
    try:
        iot.delete_role_alias(roleAlias=alias)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
