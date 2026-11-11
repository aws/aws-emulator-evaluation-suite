"""delete-webapp-customization-conflict-while-in-use."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-webapp-customization-conflict-while-in-use"
GROUP = "concurrency"
SERVICES = ["transfer"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Racing DeleteWebAppCustomization against UpdateWebAppCustomization yields success or
    ConflictException (a delete may also find it already gone), and the customization ends either
    gone (ResourceNotFoundException with its exact message) or titled with a submitted title."""
    web_app_id = _create_web_app(ctx)
    transfer = ctx.client("transfer")

    update_titles = [f"sim2real-inuse-{i}" for i in range(4)]

    def _update(title: str):
        return ("update", title, _error_code(
            lambda: transfer.update_web_app_customization(WebAppId=web_app_id, Title=title)
        ))

    def _delete(_i: int):
        return ("delete", None, _error_code(
            lambda: transfer.delete_web_app_customization(WebAppId=web_app_id)
        ))

    tasks = [(_update, t) for t in update_titles] + [(_delete, i) for i in range(2)]
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        results = list(pool.map(lambda t: t[0](t[1]), tasks))

    update_errors = {err for kind, _, err in results if kind == "update"}
    delete_errors = {err for kind, _, err in results if kind == "delete"}
    update_codes = {err[0] if err else None for err in update_errors}
    delete_codes = {err[0] if err else None for err in delete_errors}
    assert update_codes <= {None, "ConflictException"}, (
        f"unexpected error code(s) among update racers: {update_codes}"
    )
    # A delete that runs after the other delete, with no update in between, finds no customization.
    assert delete_codes <= {None, "ConflictException", "ResourceNotFoundException"}, (
        f"unexpected error code(s) among delete racers: {delete_codes}"
    )
    conflict_messages = {
        (kind, err[1]) for kind, _, err in results if err and err[0] == "ConflictException"
    }
    assert conflict_messages <= {
        ("update", "Unable to update WebApp customization"),
        ("delete", "Unable to delete WebApp customization"),
    }, f"unexpected ConflictException message(s): {conflict_messages}"
    assert any(err is None for _, _, err in results), "expected at least one racer to succeed"

    # Independent terminal read: one coherent outcome, never a mix of racers' writes.
    try:
        final_title = transfer.describe_web_app_customization(WebAppId=web_app_id)[
            "WebAppCustomization"
        ].get("Title")
    except ClientError as exc:
        assert exc.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected either a coherent surviving customization or ResourceNotFoundException "
            f"after the race, got {exc.response['Error']['Code']}"
        )
        assert exc.response["Error"].get("Message") == (
            f"The WebApp {web_app_id} doesn't have customization"
        ), f"unexpected not-found message: {exc.response['Error'].get('Message')!r}"
    else:
        assert final_title in update_titles, (
            f"surviving customization Title {final_title!r} is neither deleted nor one of the "
            f"racers' own submitted titles {update_titles} -- a half-applied mix"
        )

    def _cleanup_customization():
        try:
            transfer.delete_web_app_customization(WebAppId=web_app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_customization)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")


def _create_web_app(ctx):
    from botocore.exceptions import ClientError

    sso = ctx.client("sso-admin")
    try:
        instances = sso.list_instances().get("Instances", [])
    except ClientError as exc:
        raise AssertionError(f"IAM Identity Center (sso-admin) not reachable: {exc}") from exc
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # CreateInstance provisions a standalone account instance of IAM Identity Center, an
        # account-global singleton, so it is adopted rather than torn down in cleanup.
        try:
            instance_arn = sso.create_instance()["InstanceArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise AssertionError(
                    f"CreateInstance (standalone IAM Identity Center account instance) failed: {exc}"
                ) from exc
            # Lost a race with a concurrent creator; adopt whatever now exists.
            instances = sso.list_instances().get("Instances", [])
            assert instances, (
                "CreateInstance raised ConflictException (instance already exists) but "
                "ListInstances still returns none"
            )
            instance_arn = instances[0]["InstanceArn"]

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
    return web_app_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
