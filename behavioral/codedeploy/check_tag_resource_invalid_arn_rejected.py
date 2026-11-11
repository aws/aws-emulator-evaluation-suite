"""tag-resource-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-rejected"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']


def _account_id(ctx):
    cached = getattr(ctx, "_cd_account_id", None)
    if cached is None:
        cached = ctx.account
        ctx._cd_account_id = cached
    return cached


def _application_arn(ctx, name):
    return f"arn:aws:codedeploy:{ctx.region}:{_account_id(ctx)}:application:{name}"


def _create_application(ctx):
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    return name


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Positive control: TagResource on a real application ARN succeeds and is visible via an
    independent read. Then TagResource with a non-ARN string -> InvalidArnException. A malformed
    ARN can never become valid, so there is no restore leg."""
    cd = ctx.client("codedeploy")

    name = _create_application(ctx)
    arn = _application_arn(ctx, name)
    cd.tag_resource(ResourceArn=arn, Tags=[{"Key": "A", "Value": "B"}])
    live_tags = cd.list_tags_for_resource(ResourceArn=arn)["Tags"]
    kv = {t["Key"]: t["Value"] for t in live_tags}
    assert kv.get("A") == "B", f"positive control: expected tag A=B, got {live_tags!r}"

    error = _client_error(
        lambda: cd.tag_resource(ResourceArn="not-a-valid-arn", Tags=[{"Key": "A", "Value": "B"}])
    )
    assert error == ("InvalidArnException", "Invalid ARN: not-a-valid-arn"), (
        f"expected InvalidArnException, got {error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
