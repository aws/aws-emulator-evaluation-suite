"""op-contract-untagResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-untagResource"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the requested keys and leaves the rest
    intact; untagging a nonexistent resource ARN yields ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    appconfig.tag_resource(ResourceArn=app_arn, Tags={"Owner": "team-a", "Stage": "dev"})
    appconfig.untag_resource(ResourceArn=app_arn, TagKeys=["Stage"])
    tags = appconfig.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert tags == {"Owner": "team-a"}, f"expected only Owner to remain, got {tags}"

    bogus_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/0000000"
    err = _error(lambda: appconfig.untag_resource(ResourceArn=bogus_arn, TagKeys=["Owner"]))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = f"Resource with ARN {bogus_arn} could not be found for account {account_id}."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # the real resource's remaining tag is untouched by the failed call
    tags_after = appconfig.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert tags_after == {"Owner": "team-a"}, f"expected Owner untouched by the failed call, got {tags_after}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected UntagResource to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
