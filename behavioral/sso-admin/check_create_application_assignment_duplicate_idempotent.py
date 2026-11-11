"""create-application-assignment-duplicate-idempotent."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-application-assignment-duplicate-idempotent"
GROUP = "concurrency"
SERVICES = ["sso-admin"]

# The exact message AWS returns to a racer that loses the duplicate-assignment race.
_CONFLICT_MESSAGE = "There is a conflicting operation in process."


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Five concurrent CreateApplicationAssignment calls for one application and group each succeed or fail with
    ConflictException and the exact message, and ListApplicationAssignments shows exactly one assignment for the
    group."""
    from concurrent.futures import ThreadPoolExecutor

    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)
    identity_store_id = sso.describe_instance(InstanceArn=instance_arn)["IdentityStoreId"]
    group_id = _create_group(ctx, identity_store_id)

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))
    ctx.on_cleanup(
        lambda: _safe(
            lambda: sso.delete_application_assignment(
                ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP"
            )
        )
    )

    def _assign_once(_i):
        from botocore.exceptions import ClientError

        try:
            sso.create_application_assignment(ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP")
            return ("ok", None, None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"], err.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(_assign_once, range(5)))

    # Every racer either succeeds outright (idempotent create) or is rejected as a conflict;
    # either way nothing but a single logical assignment can ever result.
    for outcome, code, message in results:
        if outcome == "ok":
            continue
        assert code == "ConflictException", (outcome, code, message)
        assert message == _CONFLICT_MESSAGE, (
            f"expected message {_CONFLICT_MESSAGE!r}, got {message!r}"
        )

    listed = sso.list_application_assignments(ApplicationArn=app_arn)["ApplicationAssignments"]
    matches = [a for a in listed if a["PrincipalId"] == group_id]
    assert len(matches) == 1, f"expected exactly one surviving assignment for {group_id}, got {matches}"


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]
        ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _pick_oauth_provider_arn(ctx):

    sso = ctx.client("sso-admin")
    providers = {p["ApplicationProviderArn"] for p in sso.list_application_providers().get("ApplicationProviders", [])}
    custom_arn = "arn:aws:sso::aws:applicationProvider/custom"
    if custom_arn not in providers:
        raise AssertionError("the generic customer-managed OAuth2 application provider is not available in this partition")
    return custom_arn


def _create_group(ctx, identity_store_id):
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id))
    return group_id


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

