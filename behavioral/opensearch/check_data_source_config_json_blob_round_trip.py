"""data-source-config-json-blob-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "data-source-config-json-blob-round-trip"
GROUP = "data-plane"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A data source Description with special characters, set by AddDataSource then
    UpdateDataSource, is returned byte-for-byte by GetDataSource after each write."""
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx)
    _create_minimal_domain(ctx, domain_name)

    ds_name = "sim2real_ds_1"
    # DataSourceType has no free-form config field, so Description carries the content; its
    # pattern permits backslash, @#%*+=:?./! and whitespace.
    desc_v1 = "config_v1: path=/etc/data.json ratio=99.9% ok?! ref\\path -end"
    client.add_data_source(
        DomainName=domain_name,
        Name=ds_name,
        DataSourceType={"S3GlueDataCatalog": {"RoleArn": _dummy_role_arn(ctx)}},
        Description=desc_v1,
    )
    ctx.on_cleanup(lambda: client.delete_data_source(DomainName=domain_name, Name=ds_name))

    got1 = client.get_data_source(DomainName=domain_name, Name=ds_name)
    assert got1["Description"] == desc_v1, f"description did not round-trip on add: {got1!r}"

    desc_v2 = "config_v2: batch#42 * threshold=0.005 - retries: 3 / mode=strict! note_ok"
    client.update_data_source(
        DomainName=domain_name,
        Name=ds_name,
        DataSourceType={"S3GlueDataCatalog": {"RoleArn": _dummy_role_arn(ctx)}},
        Description=desc_v2,
    )
    got2 = client.get_data_source(DomainName=domain_name, Name=ds_name)
    assert got2["Description"] == desc_v2, f"description did not round-trip on update: {got2!r}"
    assert got2["Description"] != desc_v1, (
        f"update did not change Description: still {got2['Description']!r} (expected != {desc_v1!r})"
    )


def _domain_name(ctx) -> str:
    raw = ctx.unique_name("sim2r-dp-").lower().replace("_", "-")
    cleaned = "".join(ch for ch in raw if ch.isalnum() or ch == "-")
    if not cleaned[0].isalpha():
        cleaned = "a" + cleaned
    return cleaned[:28]


def _dummy_role_arn(ctx) -> str:
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:iam::{account}:role/sim2real-nonexistent-role"


def _create_minimal_domain(ctx, name):
    client = ctx.client("opensearch")
    client.create_domain(
        DomainName=name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: client.delete_domain(DomainName=name))
    return _wait_domain_active(ctx, name)


def _wait_domain_active(ctx, name, timeout_s=1800.0):
    client = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = client.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s (last={status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
