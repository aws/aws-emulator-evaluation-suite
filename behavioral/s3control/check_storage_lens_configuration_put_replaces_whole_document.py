"""storage-lens-configuration-put-replaces-whole-document."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "storage-lens-configuration-put-replaces-whole-document"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c1", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """A second PutStorageLensConfiguration under the same id replaces the document, never merges.

    Exclude and prefix metrics vanish, Include appears, IsEnabled flips, and the ARN is unchanged.
    """
    s3c = ctx.client("s3control")
    account = ctx.client("sts").get_caller_identity()["Account"]
    config_id = ctx.unique_name("sim2real-behav-slrep-")
    excluded = ctx.unique_name("sim2real-behav-slex-")
    included = ctx.unique_name("sim2real-behav-slin-")

    first = {
        "Id": config_id,
        "IsEnabled": True,
        "AccountLevel": {
            "ActivityMetrics": {"IsEnabled": True},
            "BucketLevel": {
                "ActivityMetrics": {"IsEnabled": True},
                "PrefixLevel": {"StorageMetrics": {"IsEnabled": True}},
            },
        },
        "Exclude": {"Buckets": [f"arn:aws:s3:::{excluded}"]},
    }
    s3c.put_storage_lens_configuration(
        AccountId=account, ConfigId=config_id, StorageLensConfiguration=first,
        Tags=[{"Key": "sim2real", "Value": "slrep"}],
    )
    ctx.on_cleanup(lambda: _drop_storage_lens(s3c, account, config_id))
    stored = s3c.get_storage_lens_configuration(AccountId=account, ConfigId=config_id)[
        "StorageLensConfiguration"
    ]
    assert "Exclude" in stored and "Include" not in stored, (
        f"the first document read back as {stored!r}; it should carry Exclude and no Include"
    )
    arn = stored["StorageLensArn"]

    second = {
        "Id": config_id,
        "IsEnabled": False,
        "AccountLevel": {"BucketLevel": {}},
        "Include": {"Buckets": [f"arn:aws:s3:::{included}"]},
    }
    s3c.put_storage_lens_configuration(
        AccountId=account, ConfigId=config_id, StorageLensConfiguration=second
    )
    replaced = s3c.get_storage_lens_configuration(AccountId=account, ConfigId=config_id)[
        "StorageLensConfiguration"
    ]

    assert "Exclude" not in replaced, (
        f"the Exclude clause from the first document survived the replacement: {replaced!r}"
    )
    assert replaced["Include"] == second["Include"], (
        f"Include read back as {replaced.get('Include')!r}, submitted {second['Include']!r}"
    )
    assert replaced["AccountLevel"] == {"BucketLevel": {}}, (
        f"AccountLevel read back as {replaced['AccountLevel']!r}; the first document's "
        "PrefixLevel and ActivityMetrics must not have been merged in"
    )
    assert replaced["IsEnabled"] is False, (
        f"IsEnabled read back as {replaced['IsEnabled']!r} after being replaced with False"
    )
    assert replaced["StorageLensArn"] == arn, (
        f"the replacement re-minted the arn: was {arn!r}, now {replaced['StorageLensArn']!r}"
    )

    listed = {c["Id"]: c for c in _all_storage_lens_configurations(s3c, account)}
    assert listed[config_id]["IsEnabled"] is False, (
        f"the listing still reports IsEnabled {listed[config_id].get('IsEnabled')!r} — the "
        "collection view and the document view disagree"
    )
    assert len([c for c in _all_storage_lens_configurations(s3c, account)
                if c["Id"] == config_id]) == 1, (
        "the replacement created a second entry under the same id"
    )


# ===== helpers =====

def _all_storage_lens_configurations(s3c, account: str) -> list:
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
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchConfiguration":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
