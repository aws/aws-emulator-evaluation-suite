"""op-contract-tagResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-tagResource"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource and is
    additive across calls; tagging a nonexistent resource ARN yields
    ResourceNotFoundException without mutating the real resource's tags."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    appconfig.tag_resource(ResourceArn=app_arn, Tags={"Owner": "team-a"})
    tags_first = appconfig.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert tags_first == {"Owner": "team-a"}, f"expected only Owner after first tag call, got {tags_first}"

    # additive: a second TagResource call merges in a new key without dropping the first
    appconfig.tag_resource(ResourceArn=app_arn, Tags={"Stage": "dev"})
    tags = appconfig.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert tags == {"Owner": "team-a", "Stage": "dev"}, f"unexpected tags after additive call: {tags}"

    bogus_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/0000000"
    err = _error(lambda: appconfig.tag_resource(ResourceArn=bogus_arn, Tags={"X": "Y"}))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = f"Resource with ARN {bogus_arn} could not be found for account {account_id}."
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    # the real resource's tags are untouched by the failed call against the bogus ARN
    tags_after = appconfig.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert tags_after == {"Owner": "team-a", "Stage": "dev"}, (
        f"real resource's tags mutated by failed call against bogus ARN: {tags_after}"
    )


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected TagResource to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
