"""tag-resource-invalid-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-invalid-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource, UntagResource, and ListTagsForResource against a non-existent AppConfig
    resource ARN all return ResourceNotFoundException, while the same calls succeed and mutate
    tag state correctly against a real, existing application."""
    appconfig = ctx.client("appconfig")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bogus_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/zzzzzzz"

    expected_message = f"Resource with ARN {bogus_arn} could not be found for account {account_id}."

    err_tag = _error(lambda: appconfig.tag_resource(ResourceArn=bogus_arn, Tags={"k": "v"}))
    assert err_tag["Code"] == "ResourceNotFoundException", f"TagResource: expected ResourceNotFoundException, got {err_tag}"
    assert err_tag["Message"] == expected_message, (
        f"TagResource: expected message {expected_message!r}, got {err_tag['Message']!r}"
    )

    err_list = _error(lambda: appconfig.list_tags_for_resource(ResourceArn=bogus_arn))
    assert err_list["Code"] == "ResourceNotFoundException", (
        f"ListTagsForResource: expected ResourceNotFoundException, got {err_list}"
    )
    assert err_list["Message"] == expected_message, (
        f"ListTagsForResource: expected message {expected_message!r}, got {err_list['Message']!r}"
    )

    err_untag = _error(lambda: appconfig.untag_resource(ResourceArn=bogus_arn, TagKeys=["k"]))
    assert err_untag["Code"] == "ResourceNotFoundException", (
        f"UntagResource: expected ResourceNotFoundException, got {err_untag}"
    )
    assert err_untag["Message"] == expected_message, (
        f"UntagResource: expected message {expected_message!r}, got {err_untag['Message']!r}"
    )

    # Positive control: the same three operations succeed against a real application and
    # actually mutate its tag set.
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"))
    app_id = app["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))
    real_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    appconfig.tag_resource(ResourceArn=real_arn, Tags={"env": "test"})
    tags_now = appconfig.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert tags_now.get("env") == "test", f"expected env=test after TagResource, got {tags_now!r}"

    appconfig.untag_resource(ResourceArn=real_arn, TagKeys=["env"])
    tags_after = appconfig.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert "env" not in tags_after, f"expected env removed after UntagResource, still present: {tags_after!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
