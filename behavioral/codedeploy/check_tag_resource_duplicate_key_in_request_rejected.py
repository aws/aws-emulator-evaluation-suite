"""tag-resource-duplicate-key-in-request-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-duplicate-key-in-request-rejected"
GROUP = 'error-semantics'
SERVICES = ['codedeploy']

_DUPLICATE_KEY = "owner"


def _application_arn(ctx, name):
    return f"arn:aws:codedeploy:{ctx.region}:{ctx.account}:application:{name}"


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource with the same key twice in one call is rejected and leaves the
    resource's tags unchanged; sending that key once succeeds.
    """
    cd = ctx.client("codedeploy")
    name = ctx.unique_name("sim2real-behav-app-")
    cd.create_application(applicationName=name, computePlatform="Lambda")
    ctx.on_cleanup(lambda: cd.delete_application(applicationName=name))
    arn = _application_arn(ctx, name)

    _DUPLICATE_TAG = ("InvalidTagsToAddException", f"Duplicate Tag key: {_DUPLICATE_KEY}")
    expect_error(
        lambda: cd.tag_resource(
            ResourceArn=arn,
            Tags=[
                {"Key": _DUPLICATE_KEY, "Value": "platform"},
                {"Key": _DUPLICATE_KEY, "Value": "infra"},
            ],
        ),
        *_DUPLICATE_TAG,
    )
    after_refusal = cd.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_refusal == [], f"the refused call left tags behind: {after_refusal!r}"

    cd.tag_resource(ResourceArn=arn, Tags=[{"Key": _DUPLICATE_KEY, "Value": "platform"}])
    after_control = {
        t["Key"]: t["Value"] for t in cd.list_tags_for_resource(ResourceArn=arn)["Tags"]
    }
    assert after_control == {_DUPLICATE_KEY: "platform"}, (
        f"positive control: expected a single {_DUPLICATE_KEY}=platform tag, got {after_control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
