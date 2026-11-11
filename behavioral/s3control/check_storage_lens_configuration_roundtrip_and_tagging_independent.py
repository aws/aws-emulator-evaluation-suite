"""storage-lens-configuration-roundtrip-and-tagging-independent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "storage-lens-configuration-roundtrip-and-tagging-independent"
GROUP = "state-machine"
SERVICES = ["s3control"]

NO_SUCH_CONFIGURATION = "The specified configuration does not exist."


@tags("cap:c1", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """A Storage Lens configuration and its tags are independent: tagging leaves the document
    intact, untagging keeps the configuration, the tag record starts as an empty list (not a 404),
    and delete then reports NoSuchConfiguration on read and on re-delete.
    """
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    config_id = ctx.unique_name("sim2real-behav-sl-")

    submitted = {
        "Id": config_id,
        "IsEnabled": True,
        "AccountLevel": {
            "ActivityMetrics": {"IsEnabled": True},
            "BucketLevel": {
                "ActivityMetrics": {"IsEnabled": True},
                "PrefixLevel": {"StorageMetrics": {"IsEnabled": True}},
            },
        },
        "Exclude": {"Buckets": [f"arn:aws:s3:::{ctx.unique_name('sim2real-behav-slx-')}"]},
    }
    s3c.put_storage_lens_configuration(
        AccountId=account, ConfigId=config_id, StorageLensConfiguration=submitted
    )
    ctx.on_cleanup(lambda: _drop_storage_lens(s3c, account, config_id))

    stored = s3c.get_storage_lens_configuration(AccountId=account, ConfigId=config_id)[
        "StorageLensConfiguration"
    ]
    expected_arn = f"arn:aws:s3:{ctx.region}:{account}:storage-lens/{config_id}"
    assert stored["StorageLensArn"] == expected_arn, (
        f"GetStorageLensConfiguration reported StorageLensArn {stored.get('StorageLensArn')!r}, "
        f"expected the derived {expected_arn!r}"
    )
    assert stored["Id"] == config_id and stored["IsEnabled"] is True, (
        f"the configuration read back as {stored!r}"
    )
    assert stored["AccountLevel"] == submitted["AccountLevel"], (
        f"AccountLevel read back as {stored['AccountLevel']!r}, submitted "
        f"{submitted['AccountLevel']!r}"
    )
    assert stored["Exclude"] == submitted["Exclude"], (
        f"Exclude read back as {stored.get('Exclude')!r}"
    )

    listed = {
        c["Id"]: c for c in _all_storage_lens_configurations(s3c, account)
    }
    assert config_id in listed, (
        f"{config_id!r} is missing from ListStorageLensConfigurations: {sorted(listed)!r}"
    )
    assert listed[config_id]["HomeRegion"] == ctx.region, (
        f"the listing reported HomeRegion {listed[config_id].get('HomeRegion')!r}"
    )
    assert listed[config_id]["IsEnabled"] is True, (
        f"the listing reported IsEnabled {listed[config_id].get('IsEnabled')!r}"
    )

    fresh = s3c.get_storage_lens_configuration_tagging(AccountId=account, ConfigId=config_id)
    assert fresh["Tags"] == [], (
        f"an untagged configuration reported tags {fresh['Tags']!r}; the tag record starts as "
        "an empty list, not as a not-found error"
    )

    s3c.put_storage_lens_configuration_tagging(
        AccountId=account, ConfigId=config_id,
        Tags=[{"Key": "sim2real", "Value": "slcfg"}, {"Key": "owner", "Value": "test"}],
    )
    ctx.on_cleanup(lambda: _drop_storage_lens_tags(s3c, account, config_id))
    tagged = s3c.get_storage_lens_configuration_tagging(AccountId=account, ConfigId=config_id)
    assert {t["Key"]: t["Value"] for t in tagged["Tags"]} == {
        "sim2real": "slcfg", "owner": "test"
    }, f"GetStorageLensConfigurationTagging returned {tagged['Tags']!r}"

    unchanged = s3c.get_storage_lens_configuration(AccountId=account, ConfigId=config_id)[
        "StorageLensConfiguration"
    ]
    assert unchanged == stored, (
        f"tagging mutated the configuration: it is now {unchanged!r}, was {stored!r}"
    )

    s3c.delete_storage_lens_configuration_tagging(AccountId=account, ConfigId=config_id)
    after = s3c.get_storage_lens_configuration_tagging(AccountId=account, ConfigId=config_id)
    assert after["Tags"] == [], (
        f"tags survived DeleteStorageLensConfigurationTagging: {after['Tags']!r}"
    )
    survived = s3c.get_storage_lens_configuration(AccountId=account, ConfigId=config_id)[
        "StorageLensConfiguration"
    ]
    assert survived == stored, (
        "deleting the tags took the configuration with it or changed it: it is now "
        f"{survived!r}"
    )

    s3c.delete_storage_lens_configuration(AccountId=account, ConfigId=config_id)
    code, message = _error(
        lambda: s3c.get_storage_lens_configuration(AccountId=account, ConfigId=config_id)
    )
    assert code == "NoSuchConfiguration", (
        f"GetStorageLensConfiguration after the delete returned {code!r}, "
        "expected NoSuchConfiguration"
    )
    assert message == NO_SUCH_CONFIGURATION, (
        f"GetStorageLensConfiguration after the delete said {message!r}, "
        f"expected {NO_SUCH_CONFIGURATION!r}"
    )
    assert config_id not in {
        c["Id"] for c in _all_storage_lens_configurations(s3c, account)
    }, f"{config_id!r} survived the delete in ListStorageLensConfigurations"

    redelete_code, redelete_message = _error(
        lambda: s3c.delete_storage_lens_configuration(AccountId=account, ConfigId=config_id)
    )
    assert redelete_code == "NoSuchConfiguration", (
        f"deleting the already-deleted {config_id!r} again returned {redelete_code!r}, "
        "expected NoSuchConfiguration, not a second success"
    )
    assert redelete_message == NO_SUCH_CONFIGURATION, (
        f"deleting the already-deleted {config_id!r} again said {redelete_message!r}, "
        f"expected {NO_SUCH_CONFIGURATION!r}"
    )


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    """The AWS error code and message raised by ``fn``. Raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


def _all_storage_lens_configurations(s3c, account: str) -> list:
    """Every Storage Lens configuration in the account, across all pages."""
    out: list = []
    token = None
    while True:
        args = {"AccountId": account}
        if token:
            args["NextToken"] = token
        page = s3c.list_storage_lens_configurations(**args)
        out.extend(page.get("StorageLensConfigurationList", []))
        token = page.get("NextToken")
        if not token:
            return out


def _drop_storage_lens(s3c, account: str, config_id: str) -> None:
    try:
        s3c.delete_storage_lens_configuration(AccountId=account, ConfigId=config_id)
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "NoSuchConfiguration":
            raise


def _drop_storage_lens_tags(s3c, account: str, config_id: str) -> None:
    try:
        s3c.delete_storage_lens_configuration_tagging(AccountId=account, ConfigId=config_id)
    except ClientError as exc:
        if exc.response["Error"].get("Code") != "NoSuchConfiguration":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
