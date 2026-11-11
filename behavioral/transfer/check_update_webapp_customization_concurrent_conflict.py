"""update-webapp-customization-concurrent-conflict."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "update-webapp-customization-concurrent-conflict"
GROUP = "concurrency"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Concurrent UpdateWebAppCustomization calls on one web app each succeed or fail with ConflictException,
    at least one succeeds, and the stored Title is exactly one submitted title."""
    web_app_id, _role_arn = _create_web_app_or_skip(ctx)

    titles = [f"sim2real-title-{i}" for i in range(6)]

    def _attempt(title: str):
        return title, _error_code(
            lambda: ctx.client("transfer").update_web_app_customization(WebAppId=web_app_id, Title=title)
        )

    with ThreadPoolExecutor(max_workers=len(titles)) as pool:
        results = list(pool.map(_attempt, titles))

    codes = {code for _, code in results}
    assert codes <= {None, "ConflictException"}, f"unexpected error code(s) among racers: {codes}"
    successes = [title for title, code in results if code is None]
    assert successes, "expected at least one of the concurrent writers to succeed"

    final_title = ctx.client("transfer").describe_web_app_customization(WebAppId=web_app_id)[
        "WebAppCustomization"
    ]["Title"]
    assert final_title in titles, (
        f"final Title {final_title!r} is not one of the submitted titles {titles} -- "
        "state was corrupted by the concurrent writes"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _identity_center_instance_arn(ctx) -> str:
    """Create-or-adopt: an account may already carry a standalone Identity Center instance
    (an account-global singleton, at most one per account), or CreateInstance can mint one."""
    from botocore.exceptions import ClientError

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]
    try:
        instance_arn = sso.create_instance(Name=ctx.unique_name("sim2real-identity-center-"))[
            "InstanceArn"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConflictException":
            raise
        instances = sso.list_instances().get("Instances", [])
        if not instances:
            raise AssertionError(
                f"CreateInstance reported a conflict ({exc}) but ListInstances still shows none"
            ) from exc
        return instances[0]["InstanceArn"]
    # Registered before the web app's teardown, so LIFO cleanup removes the instance last.
    ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))
    for _ in range(30):
        if sso.describe_instance(InstanceArn=instance_arn).get("Status") == "ACTIVE":
            break
        time.sleep(2)
    else:
        raise AssertionError(f"Identity Center instance {instance_arn} did not become ACTIVE")
    return instance_arn


def _create_web_app_or_skip(ctx):
    from botocore.exceptions import ClientError

    instance_arn = _identity_center_instance_arn(ctx)

    iam = ctx.client("iam")
    transfer = ctx.client("transfer")
    role_name = ctx.unique_name("sim2real-behav-webapp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    try:
        web_app_id = transfer.create_web_app(
            IdentityProviderDetails={"IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["WebAppId"]
    except ClientError as exc:
        raise AssertionError(
            "CreateWebApp failed even with a discovered IAM Identity Center instance -- this "
            "feature also needs a correctly wired S3 Access Grants location/role that this "
            f"harness does not provision automatically: {exc}"
        ) from exc

    ctx.on_cleanup(lambda: transfer.delete_web_app(WebAppId=web_app_id))
    transfer.update_web_app_customization(WebAppId=web_app_id, Title="sim2real-initial")
    ctx.on_cleanup(lambda: transfer.delete_web_app_customization(WebAppId=web_app_id))
    return web_app_id, role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
