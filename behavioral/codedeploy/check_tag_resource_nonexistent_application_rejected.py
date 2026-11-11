"""tag-resource-nonexistent-application-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-application-rejected"
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


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource tags a real application but fails on an ARN naming no application with
    ApplicationDoesNotExistException; ListTagsForResource on that ARN answers an empty tag list, so the tag
    never stuck.
    """
    cd = ctx.client("codedeploy")

    live_name = ctx.unique_name("sim2real-behav-app-live-")
    cd.create_application(applicationName=live_name, computePlatform="Server")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=live_name))
    live_arn = _application_arn(ctx, live_name)

    cd.tag_resource(ResourceArn=live_arn, Tags=[{"Key": "A", "Value": "B"}])
    live_tags = cd.list_tags_for_resource(ResourceArn=live_arn)["Tags"]
    assert {"Key": "A", "Value": "B"} in live_tags, live_tags

    ghost_name = ctx.unique_name("sim2real-behav-" + "app-ghost-")
    ghost_arn = _application_arn(ctx, ghost_name)

    error = _client_error(
        lambda: cd.tag_resource(ResourceArn=ghost_arn, Tags=[{"Key": "A", "Value": "B"}])
    )
    assert (error.get("Code"), error.get("Message")) == (
        "ApplicationDoesNotExistException",
        f"No application found for name: {ghost_name}",
    ), error

    ghost_tags = cd.list_tags_for_resource(ResourceArn=ghost_arn)["Tags"]
    assert ghost_tags == [], ghost_tags


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
