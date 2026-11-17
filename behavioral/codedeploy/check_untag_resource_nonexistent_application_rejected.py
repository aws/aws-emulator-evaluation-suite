"""untag-resource-nonexistent-application-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-nonexistent-application-rejected"
GROUP = "error-semantics"
SERVICES = ["codedeploy"]


def expect_error(fn, code, message):
    """Call fn(); assert its ClientError carries exactly (code, message). An unexpected
    success raises.
    """
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == code, f"expected {code}, got {error!r}"
        assert error.get("Message") == message, f"expected message {message!r}, got {error!r}"
        return
    raise AssertionError(f"expected the call to be rejected with {code}, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UntagResource on an ARN naming no application fails with
    ApplicationDoesNotExistException; UntagResource on a real application's tag succeeds.
    """
    cd = ctx.client("codedeploy")

    ghost_name = ctx.unique_name("sim2real-behav-cdapp-ghost-")
    ghost_arn = f"arn:aws:codedeploy:{ctx.region}:{ctx.account}:application:{ghost_name}"

    _GHOST = (
        "ApplicationDoesNotExistException",
        f"No application found for name: {ghost_name}",
    )
    expect_error(lambda: cd.untag_resource(ResourceArn=ghost_arn, TagKeys=["Pipeline"]), *_GHOST)

    live_name = ctx.unique_name("sim2real-behav-cdapp-live-")
    cd.create_application(
        applicationName=live_name,
        computePlatform="Server",
        tags=[{"Key": "Pipeline", "Value": "alpha"}],
    )
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=live_name))
    live_arn = f"arn:aws:codedeploy:{ctx.region}:{ctx.account}:application:{live_name}"

    cd.untag_resource(ResourceArn=live_arn, TagKeys=["Pipeline"])
    remaining = cd.list_tags_for_resource(ResourceArn=live_arn)["Tags"]
    assert remaining == [], f"UntagResource on a real application left tags behind: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
