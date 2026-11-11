"""storage-lens-group-update-and-arn-tagging-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "storage-lens-group-update-and-arn-tagging-roundtrip"
GROUP = "state-machine"
SERVICES = ["s3control"]

NO_SUCH_CONFIGURATION = "The specified configuration does not exist."
NO_SUCH_RESOURCE = "The specified resource doesn't exist."


@tags("cap:c1", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """UpdateStorageLensGroup replaces the group's filter, and ARN-based TagResource/UntagResource
    change the group's tags without touching its filter; deletion removes both records.
    """
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    group = ctx.unique_name("sim2real-behav-slg-")

    s3c.create_storage_lens_group(
        AccountId=account,
        StorageLensGroup={"Name": group, "Filter": {"MatchAnyPrefix": ["logs/"]}},
    )
    ctx.on_cleanup(lambda: _drop_storage_lens_group(s3c, account, group))

    stored = s3c.get_storage_lens_group(AccountId=account, Name=group)["StorageLensGroup"]
    group_arn = f"arn:aws:s3:{ctx.region}:{account}:storage-lens-group/{group}"
    assert stored["StorageLensGroupArn"] == group_arn, (
        f"GetStorageLensGroup reported arn {stored.get('StorageLensGroupArn')!r}, "
        f"expected {group_arn!r}"
    )
    assert stored["Filter"] == {"MatchAnyPrefix": ["logs/"]}, (
        f"the created group's filter read back as {stored['Filter']!r}"
    )

    s3c.update_storage_lens_group(
        AccountId=account, Name=group,
        StorageLensGroup={
            "Name": group,
            "Filter": {
                "And": {
                    "MatchAnyPrefix": ["logs/"],
                    "MatchObjectSize": {"BytesGreaterThan": 1024},
                }
            },
        },
    )
    updated = s3c.get_storage_lens_group(AccountId=account, Name=group)["StorageLensGroup"]
    assert "And" in updated["Filter"], (
        f"UpdateStorageLensGroup did not replace the filter: {updated['Filter']!r}"
    )
    assert "MatchAnyPrefix" not in updated["Filter"], (
        f"the standalone MatchAnyPrefix clause survived alongside the And composite: "
        f"{updated['Filter']!r}"
    )
    assert updated["Filter"]["And"]["MatchObjectSize"] == {"BytesGreaterThan": 1024}, (
        f"the And composite read back as {updated['Filter']['And']!r}"
    )
    assert updated["StorageLensGroupArn"] == group_arn, (
        f"the update re-minted the arn: now {updated['StorageLensGroupArn']!r}"
    )

    assert s3c.list_tags_for_resource(AccountId=account, ResourceArn=group_arn)["Tags"] == [], (
        "a fresh Storage Lens group reported tags"
    )
    s3c.tag_resource(
        AccountId=account, ResourceArn=group_arn,
        Tags=[{"Key": "sim2real", "Value": "slg"}, {"Key": "team", "Value": "test"}],
    )
    ctx.on_cleanup(lambda: _untag_all(s3c, account, group_arn))
    tags_map = {
        t["Key"]: t["Value"]
        for t in s3c.list_tags_for_resource(AccountId=account, ResourceArn=group_arn)["Tags"]
    }
    assert tags_map == {"sim2real": "slg", "team": "test"}, (
        f"ListTagsForResource returned {tags_map!r}"
    )

    s3c.untag_resource(AccountId=account, ResourceArn=group_arn, TagKeys=["team"])
    remaining = {
        t["Key"]: t["Value"]
        for t in s3c.list_tags_for_resource(AccountId=account, ResourceArn=group_arn)["Tags"]
    }
    assert remaining == {"sim2real": "slg"}, (
        f"UntagResource(team) left {remaining!r}, expected only the sim2real tag"
    )
    filter_after = s3c.get_storage_lens_group(AccountId=account, Name=group)[
        "StorageLensGroup"
    ]["Filter"]
    assert filter_after == updated["Filter"], (
        f"tagging churn mutated the filter: now {filter_after!r}"
    )

    s3c.delete_storage_lens_group(AccountId=account, Name=group)
    code, message = _error(lambda: s3c.get_storage_lens_group(AccountId=account, Name=group))
    assert code == "NoSuchConfiguration", (
        f"GetStorageLensGroup after the delete returned {code!r}, expected NoSuchConfiguration"
    )
    assert message == NO_SUCH_CONFIGURATION, (
        f"GetStorageLensGroup after the delete said {message!r}, "
        f"expected {NO_SUCH_CONFIGURATION!r}"
    )
    tag_code, tag_message = _error(
        lambda: s3c.list_tags_for_resource(AccountId=account, ResourceArn=group_arn)
    )
    assert tag_code == "NoSuchResource", (
        f"ListTagsForResource for the deleted group returned {tag_code!r}, "
        "expected NoSuchResource"
    )
    assert tag_message == NO_SUCH_RESOURCE, (
        f"ListTagsForResource for the deleted group said {tag_message!r}, "
        f"expected {NO_SUCH_RESOURCE!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The AWS error code and message raised by ``fn``. Raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _drop_storage_lens_group(s3c, account: str, name: str) -> None:
    try:
        s3c.delete_storage_lens_group(AccountId=account, Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfiguration":
            raise


def _untag_all(s3c, account: str, arn: str) -> None:
    try:
        keys = [
            t["Key"]
            for t in s3c.list_tags_for_resource(AccountId=account, ResourceArn=arn)["Tags"]
        ]
        if keys:
            s3c.untag_resource(AccountId=account, ResourceArn=arn, TagKeys=keys)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResource":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
