"""create-backend-environment-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-backend-environment-lifecycle"
GROUP = "state"
SERVICES = ["amplify"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBackendEnvironment stores stackName as opaque metadata (no stack, a real stack, or a
    nonexistent stack are all accepted, read back, listed and deleted), while a malformed
    environmentName, a missing app and a missing environment are refused with exact errors."""
    amplify = ctx.client("amplify")
    cfn = ctx.client("cloudformation")
    app_id = _create_app(ctx)

    # Positive control 1: stackName/deploymentArtifacts are optional — a bare record with
    # nothing attached is accepted, independently readable, listed, and cleanly deletable.
    env_bare = _env_name("o")
    created_bare = amplify.create_backend_environment(appId=app_id, environmentName=env_bare)[
        "backendEnvironment"
    ]
    assert created_bare["environmentName"] == env_bare, created_bare
    ctx.on_cleanup(
        lambda: _ignore(
            lambda: amplify.delete_backend_environment(appId=app_id, environmentName=env_bare)
        )
    )
    fetched_bare = amplify.get_backend_environment(appId=app_id, environmentName=env_bare)[
        "backendEnvironment"
    ]
    assert fetched_bare["environmentName"] == env_bare, fetched_bare
    listed_bare = [
        e["environmentName"]
        for e in amplify.list_backend_environments(appId=app_id)["backendEnvironments"]
    ]
    assert env_bare in listed_bare, listed_bare
    amplify.delete_backend_environment(appId=app_id, environmentName=env_bare)
    err_bare_gone = _client_error(
        lambda: amplify.get_backend_environment(appId=app_id, environmentName=env_bare)
    )
    assert err_bare_gone == _env_missing(env_bare), err_bare_gone
    err_bare_delete_again = _client_error(
        lambda: amplify.delete_backend_environment(appId=app_id, environmentName=env_bare)
    )
    assert err_bare_delete_again == _env_missing(env_bare), err_bare_delete_again

    # Positive control 2: a real, CREATE_COMPLETE CloudFormation stack is accepted verbatim as
    # opaque metadata, regardless of its structure.
    env_real_stack = _env_name("r")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    template = (
        '{"Resources":{"Handle":{"Type":"AWS::CloudFormation::WaitConditionHandle"}}}'
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )
    ctx.on_cleanup(lambda: _ignore(lambda: cfn.delete_stack(StackName=stack_name)))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 60}
    )

    artifacts = ctx.unique_name("artifacts")
    created_real = amplify.create_backend_environment(
        appId=app_id,
        environmentName=env_real_stack,
        stackName=stack_name,
        deploymentArtifacts=artifacts,
    )["backendEnvironment"]
    assert created_real["stackName"] == stack_name, created_real
    assert created_real["deploymentArtifacts"] == artifacts, created_real
    ctx.on_cleanup(
        lambda: _ignore(
            lambda: amplify.delete_backend_environment(
                appId=app_id, environmentName=env_real_stack
            )
        )
    )
    fetched_real = amplify.get_backend_environment(appId=app_id, environmentName=env_real_stack)[
        "backendEnvironment"
    ]
    assert fetched_real["stackName"] == stack_name, fetched_real
    amplify.delete_backend_environment(appId=app_id, environmentName=env_real_stack)
    err_real_gone = _client_error(
        lambda: amplify.get_backend_environment(appId=app_id, environmentName=env_real_stack)
    )
    assert err_real_gone == _env_missing(env_real_stack), err_real_gone

    # stackName is never checked against CloudFormation: a name with no matching stack is
    # accepted as readily.
    env_fake_stack = _env_name("f")
    fake_stack_name = ctx.unique_name("sim2real-behav-nostack-")
    created_fake = amplify.create_backend_environment(
        appId=app_id, environmentName=env_fake_stack, stackName=fake_stack_name
    )["backendEnvironment"]
    assert created_fake["stackName"] == fake_stack_name, created_fake
    amplify.delete_backend_environment(appId=app_id, environmentName=env_fake_stack)
    err_fake_gone = _client_error(
        lambda: amplify.get_backend_environment(appId=app_id, environmentName=env_fake_stack)
    )
    assert err_fake_gone == _env_missing(env_fake_stack), err_fake_gone

    # Everything created above was deleted, so the app's environment list is empty again.
    listed = amplify.list_backend_environments(appId=app_id)["backendEnvironments"]
    assert listed == [], listed

    # environmentName must be 2-10 lowercase letters (stricter than the model); the three
    # accepted names above make this refusal about the name alone.
    bad_name = ctx.unique_name("env")
    err_bad_name = _client_error(
        lambda: amplify.create_backend_environment(appId=app_id, environmentName=bad_name)
    )
    assert err_bad_name == (
        "BadRequestException",
        f"Failed to create backend environment.The environment name {bad_name} is invalid. "
        "Environment name should be between 2 and 10 characters (only lowercase alphabets).",
    ), err_bad_name

    # Real validation boundary 2: the parent appId itself does not exist.
    err_bad_app = _client_error(
        lambda: amplify.create_backend_environment(
            appId="dnonexistent00000000",
            environmentName=_env_name("n"),
            stackName=ctx.unique_name("stack2"),
        )
    )
    assert err_bad_app == ("NotFoundException", "App dnonexistent00000000 not found."), err_bad_app

    # get/delete on a validly-named environment that was never created hit the same
    # not-found boundary.
    env_get_missing = _env_name("g")
    err_get_missing = _client_error(
        lambda: amplify.get_backend_environment(appId=app_id, environmentName=env_get_missing)
    )
    assert err_get_missing == _env_missing(env_get_missing), err_get_missing
    env_delete_missing = _env_name("d")
    err_delete_missing = _client_error(
        lambda: amplify.delete_backend_environment(appId=app_id, environmentName=env_delete_missing)
    )
    assert err_delete_missing == _env_missing(env_delete_missing), err_delete_missing



def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _env_name(tag: str) -> str:
    """A valid Amplify backend `environmentName`.

    Undocumented in the Smithy model (which models it as 1-255 chars, any pattern), but real
    AWS rejects with BadRequestException any name that isn't 2-10 lowercase letters. Using
    ctx.unique_name() here would confound every rejection test below with a name-format error,
    making the intended boundary (stack compatibility / existence) untestable.
    """
    import random
    import string

    return (tag[:1] + "".join(random.choices(string.ascii_lowercase, k=7)))[:10]


def _env_missing(env: str) -> tuple[str, str]:
    """The (code, message) AWS returns for a backend environment that does not exist."""
    return "NotFoundException", f"BackendEnvironment {env} does not exist."


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "StackNotFoundException", "ValidationError") or (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" not in exc.response["Error"]["Message"]
        ):
            raise


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return its (code, message); an unexpected success raises, so an emulator
    accepting a call real AWS refuses never reads as a mere code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError, call succeeded: {result!r}")


def _create_app(ctx) -> str:
    import random
    import time

    from botocore.exceptions import ClientError

    amplify = ctx.client("amplify")
    name = ctx.unique_name("sim2real-amplify-app-")
    delay = 10.0
    deadline = time.monotonic() + 900.0
    app = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            app = amplify.create_app(name=name, tags=_mgmt_tags())["app"]
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "BadRequestException" and "Rate exceeded" in str(e):
                last_exc = e
                time.sleep(min(delay + random.uniform(0, delay * 0.5), max(deadline - time.monotonic(), 0)))
                delay = min(delay * 1.6, 60.0)
                continue
            raise
    if app is None:
        raise last_exc
    ctx.on_cleanup(lambda: _ignore(lambda: amplify.delete_app(appId=app["appId"])))
    return app["appId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
