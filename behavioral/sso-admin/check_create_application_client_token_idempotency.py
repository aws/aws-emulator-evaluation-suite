"""create-application-client-token-idempotency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-application-client-token-idempotency"
GROUP = "state-machine"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Replaying CreateApplication with the same ClientToken returns the same ARN and one application; the token
    with another Name fails with ConflictException and creates nothing; after delete, describe and update fail with
    ResourceNotFoundException."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)
    name = ctx.unique_name("sim2real-behav-app-")
    token = ctx.unique_name("sim2real-behav-token-")

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=name,
        ClientToken=token,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sso.delete_application(ApplicationArn=app_arn)))

    # Replaying the identical request (same ClientToken, same Name) is idempotent.
    replay_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=name,
        ClientToken=token,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ApplicationArn"]
    assert replay_arn == app_arn, f"replaying an identical CreateApplication returned {replay_arn!r}, expected the original {app_arn!r}"

    before = sso.list_applications(InstanceArn=instance_arn)["Applications"]
    before_count = sum(1 for a in before if a["ApplicationArn"] == app_arn)
    assert before_count == 1, f"expected exactly one application at {app_arn!r} after the idempotent replay, found {before_count}"

    # Reusing the same ClientToken with a different Name is a conflict, not a second app.
    code, message = _error(
        lambda: sso.create_application(
            InstanceArn=instance_arn,
            ApplicationProviderArn=provider_arn,
            Name=ctx.unique_name("sim2real-behav-app-other-"),
            ClientToken=token,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    assert code == "ConflictException", f"reusing ClientToken {token!r} with a different Name returned {code!r}, expected ConflictException"
    assert message == "The request parameters are different from that of a previous request", message

    # Effect absent: still exactly the one application, still under its original name.
    described = sso.describe_application(ApplicationArn=app_arn)
    assert described["Name"] == name, f"the application's Name changed to {described['Name']!r} after the rejected reuse, expected it to stay {name!r}"
    after = sso.list_applications(InstanceArn=instance_arn)["Applications"]
    after_count = sum(1 for a in after if a["ApplicationArn"] == app_arn)
    assert after_count == 1, f"expected exactly one application at {app_arn!r} after the rejected reuse, found {after_count}"

    # Delete is a real terminal state: an independent read and a later mutation both see it gone.
    sso.delete_application(ApplicationArn=app_arn)
    code_describe, msg_describe = _error(lambda: sso.describe_application(ApplicationArn=app_arn))
    assert code_describe == "ResourceNotFoundException", f"describing the deleted application returned {code_describe!r}, expected ResourceNotFoundException"
    assert msg_describe == f"No resource found for application arn: {app_arn}", msg_describe
    code_update, msg_update = _error(
        lambda: sso.update_application(ApplicationArn=app_arn, Name=ctx.unique_name("sim2real-behav-app-renamed-"))
    )
    assert code_update == "ResourceNotFoundException", f"updating the deleted application returned {code_update!r}, expected ResourceNotFoundException"
    assert msg_update == f"No resource found for application arn: {app_arn}", msg_update


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]
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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts a call AWS refuses fails loudly rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    """Teardown for a resource the check may already have deleted itself."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

