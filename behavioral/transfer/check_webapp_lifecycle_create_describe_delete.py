"""webapp-lifecycle-create-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webapp-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateWebApp is describable via DescribeWebApp; DeleteWebApp removes it, DescribeWebApp 404s,
    and a subsequent mutation (UpdateWebApp) on the dead id fails the same way."""
    instances = _identity_center_instances(ctx)
    instance_arn = instances[0]["InstanceArn"]

    tf = ctx.client("transfer")
    role_arn = _create_transfer_role(ctx)

    resp = _retry_role_propagation(
        lambda: tf.create_web_app(
            IdentityProviderDetails={
                "IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}
            },
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    web_app_id = resp["WebAppId"]
    ctx.on_cleanup(lambda: _safe_delete_web_app(tf, web_app_id))

    described = tf.describe_web_app(WebAppId=web_app_id)["WebApp"]
    assert described["WebAppId"] == web_app_id, (
        f"expected DescribeWebApp to return WebAppId={web_app_id!r}, got {described.get('WebAppId')!r}"
    )

    tf.delete_web_app(WebAppId=web_app_id)

    code, message = _error(lambda: tf.describe_web_app(WebAppId=web_app_id))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeWebApp on a deleted WebAppId to return ResourceNotFoundException, got {code!r}"
    )
    assert message == "Unknown WebApp", f"expected message 'Unknown WebApp', got {message!r}"

    update_code, update_message = _error(
        lambda: tf.update_web_app(WebAppId=web_app_id, WebAppUnits={"Provisioned": 1})
    )
    assert update_code == "ResourceNotFoundException", (
        "expected UpdateWebApp on a deleted WebAppId to also fail with ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    assert update_message == "Unknown WebApp", f"expected message 'Unknown WebApp', got {update_message!r}"


def _identity_center_instances(ctx):
    """The account's IAM Identity Center instances, creating one if the account has none.

    One instance is allowed per account and other checks may rely on it, so it is never deleted.
    """
    import time

    from botocore.exceptions import ClientError

    sso_idc = ctx.client("sso-admin")
    try:
        instances = sso_idc.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(
            f"cannot query IAM Identity Center instances ({exc.response['Error']['Code']})"
        ) from exc
    if not instances:
        sso_idc.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    deadline = time.time() + 120
    while time.time() < deadline:
        found = sso_idc.list_instances().get("Instances", [])
        for inst in found:
            if inst.get("Status") == "CREATE_FAILED":
                raise AssertionError(f"IAM Identity Center instance creation failed: {inst}")
        if any(i.get("Status") == "ACTIVE" and "IdentityStoreId" in i for i in found):
            return found
        time.sleep(3)
    raise AssertionError(
        "IAM Identity Center instance did not become ACTIVE with an IdentityStoreId within 120s"
    )


def _create_transfer_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "transfer.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    return role_arn


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_web_app(tf, web_app_id: str) -> None:
    try:
        tf.delete_web_app(WebAppId=web_app_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_role_propagation(fn, attempts: int = 6, delay_s: float = 3.0):
    """Retry a call that depends on a just-created IAM role, tolerating IAM's eventual consistency."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
