"""create-component-version-access-denied-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-component-version-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["greengrassv2"]
SESSION_NAME = "sim2real-ggv2-behavioral-check"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller assuming an IAM role with no attached permissions gets AccessDeniedException
    from CreateComponentVersion, no component is registered under that name, and the same
    call with the normal (permitted) credentials in this file succeeds (positive control)."""
    gg = ctx.client("greengrassv2")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-ggv2-noperm-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    creds = _assume_role_with_retry(sts, role_arn, timeout_s=45)
    denied_client = ctx.client(
        "greengrassv2",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    denied_name = ctx.unique_name("sim2real-ggv2-denied-comp-")
    code, message = _error_code(
        lambda: denied_client.create_component_version(inlineRecipe=_make_recipe(denied_name, "1.0.0"))
    )
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException from the no-permission role, got {code!r}"
    )
    expected = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{SESSION_NAME} is not authorized "
        f"to perform: greengrass:CreateComponentVersion on resource: "
        f"arn:aws:greengrass:{ctx.region}:{account_id}:components:{denied_name} because no "
        f"identity-based policy allows the greengrass:CreateComponentVersion action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    private_components = gg.list_components(scope="PRIVATE")["components"]
    assert not any(c["componentName"] == denied_name for c in private_components), (
        f"denied component {denied_name!r} must not appear in list_components "
        "after its create was rejected with AccessDeniedException"
    )

    allowed_name = ctx.unique_name("sim2real-ggv2-allowed-comp-")
    resp = gg.create_component_version(
        inlineRecipe=_make_recipe(allowed_name, "1.0.0"),
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_ignore_missing(gg, resp["arn"]))

    described = gg.describe_component(arn=resp["arn"])
    assert described["componentName"] == allowed_name, (
        f"expected an independent describe_component read of {resp['arn']!r} to report "
        f"componentName {allowed_name!r} (the positive control, same credentials the "
        f"denied call was missing), got {described.get('componentName')!r}"
    )


def _make_recipe(name: str, version: str) -> bytes:
    recipe = {
        "RecipeFormatVersion": "2020-01-25",
        "ComponentName": name,
        "ComponentVersion": version,
        "ComponentDescription": "access-denied test component",
        "ComponentPublisher": "sim2real",
        "Manifests": [{"Platform": {"os": "linux"}, "Lifecycle": {}}],
    }
    return json.dumps(recipe).encode("utf-8")


def _assume_role_with_retry(sts, role_arn: str, timeout_s: float = 45.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(
                RoleArn=role_arn, RoleSessionName=SESSION_NAME
            )["Credentials"]
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"role never became assumable: {last_err}")


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the no-permission role's call to be denied, but it SUCCEEDED and "
        f"returned {result!r}"
    )


def _delete_ignore_missing(gg, arn: str) -> None:
    try:
        gg.delete_component(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
