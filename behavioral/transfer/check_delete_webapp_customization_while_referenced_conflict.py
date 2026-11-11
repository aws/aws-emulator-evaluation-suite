"""delete-webapp-customization-while-referenced-conflict."""
from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-webapp-customization-while-referenced-conflict"
GROUP = "concurrency"
SERVICES = ["transfer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing Update/DeleteWebAppCustomization: each racer succeeds or gets ConflictException, one
    lands, and the final state is coherent (customization gone, or its title is the update)."""
    sso = ctx.client("sso-admin")
    instance_arn = _find_or_create_identity_center_instance(ctx, sso)

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-transfer-webapp-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "transfer.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    transfer = ctx.client("transfer")
    web_app_id = transfer.create_web_app(
        IdentityProviderDetails={"IdentityCenterConfig": {"InstanceArn": instance_arn, "Role": role_arn}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WebAppId"]
    ctx.on_cleanup(lambda: transfer.delete_web_app(WebAppId=web_app_id))

    transfer.update_web_app_customization(WebAppId=web_app_id, Title="original-title")
    ctx.on_cleanup(
        lambda: _best_effort(lambda: transfer.delete_web_app_customization(WebAppId=web_app_id))
    )

    barrier = threading.Barrier(2)
    outcomes: dict[str, str | None] = {}

    def _update() -> None:
        barrier.wait()
        try:
            transfer.update_web_app_customization(WebAppId=web_app_id, Title="updated-title")
            outcomes["update"] = None
        except ClientError as exc:
            outcomes["update"] = exc.response["Error"]["Code"]

    def _delete() -> None:
        barrier.wait()
        try:
            transfer.delete_web_app_customization(WebAppId=web_app_id)
            outcomes["delete"] = None
        except ClientError as exc:
            outcomes["delete"] = exc.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_update), pool.submit(_delete)]
        for f in futures:
            f.result()

    # AWS may report success for both racers with the delete silently winning, so only
    # final-state coherence is asserted, not that the loser is told it lost.
    codes = set(outcomes.values())
    assert codes <= {None, "ConflictException"}, (
        f"unexpected error code(s) among racers, expected only success or ConflictException, "
        f"got outcomes={outcomes}"
    )
    assert any(v is None for v in outcomes.values()), (
        f"expected at least one racer to succeed, got outcomes={outcomes}"
    )

    try:
        described = transfer.describe_web_app_customization(WebAppId=web_app_id)
    except ClientError as exc:
        final_code = exc.response["Error"]["Code"]
        final_message = exc.response["Error"].get("Message")
        assert final_code == "ResourceNotFoundException", (
            f"describe after the race failed with an unexpected code={final_code}, outcomes={outcomes}"
        )
        assert final_message == f"The WebApp {web_app_id} doesn't have customization", (
            f"unexpected not-found message: {final_message!r}"
        )
    else:
        assert described["WebAppCustomization"]["Title"] == "updated-title", (
            f"customization survived the race but its title is not the submitted update "
            f"(half-applied write), got={described['WebAppCustomization'].get('Title')!r} "
            f"outcomes={outcomes}"
        )


def _find_or_create_identity_center_instance(ctx, sso) -> str:
    """Reuse the enabled IAM Identity Center instance or create one; only a created one is
    cleaned up, since it is an account-global singleton."""
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]
    try:
        instance_arn = sso.create_instance(
            Name=ctx.unique_name("sim2real-transfer-webapp-")
        )["InstanceArn"]
    except ClientError as exc:
        raise AssertionError(
            "no IAM Identity Center instance is enabled in this account and "
            f"sso-admin CreateInstance to provision one was refused: {exc}"
        ) from exc
    ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))
    return instance_arn


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
