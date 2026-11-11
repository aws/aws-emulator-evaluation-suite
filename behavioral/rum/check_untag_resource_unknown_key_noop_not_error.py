"""untag-resource-unknown-key-noop-not-error."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-unknown-key-noop-not-error"
GROUP = "error-semantics"
SERVICES = ["rum"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a key that was never applied succeeds as a no-op and leaves the existing tags
    exactly as they were."""
    rum = ctx.client("rum")
    app = _create_app_monitor(ctx)
    rum.tag_resource(ResourceArn=app["arn"], Tags={"Team": "rum-fidelity"})

    before = rum.list_tags_for_resource(ResourceArn=app["arn"])["Tags"]
    assert before == {"Team": "rum-fidelity"}, (
        f"tag_resource did not apply the expected tag set: {before!r} != {{'Team': 'rum-fidelity'}}"
    )

    # No exception for a key that was never applied.
    rum.untag_resource(ResourceArn=app["arn"], TagKeys=["NeverAppliedKey"])

    after = rum.list_tags_for_resource(ResourceArn=app["arn"])["Tags"]
    assert after == before, "untagging a never-applied key must not disturb existing tags"


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _app_monitor_arn(ctx, name):
    return f"arn:aws:rum:{ctx.region}:{_account_id(ctx)}:appmonitor/{name}"


def _create_app_monitor(ctx, name=None, **kwargs):
    rum = ctx.client("rum")
    name = name or ctx.unique_name("sim2real-rum-am-")
    kwargs.setdefault("Domain", "example.com")
    resp = rum.create_app_monitor(Name=name, **kwargs)

    def _cleanup():
        try:
            rum.delete_app_monitor(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return {"name": name, "id": resp["Id"], "arn": _app_monitor_arn(ctx, name)}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
