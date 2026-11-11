"""op-contract-listTagsForResource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listTagsForResource"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource reflects exactly the tags applied via TagResource;
    a well-formed but nonexistent resource ARN yields ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    appconfig.tag_resource(ResourceArn=app_arn, Tags={"Team": "platform", "Stage": "test"})

    tags = appconfig.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert tags == {"Team": "platform", "Stage": "test"}, f"unexpected tags: {tags}"

    bogus_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/0000000"
    err = _error(lambda: appconfig.list_tags_for_resource(ResourceArn=bogus_arn))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']}"
    assert err["Message"] == f"Resource with ARN {bogus_arn} could not be found for account {account_id}.", (
        f"unexpected message: {err['Message']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
