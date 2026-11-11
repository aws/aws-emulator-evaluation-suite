"""overly-permissive-index-mapping-type-change-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "overly-permissive-index-mapping-type-change-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIndex must reject changing an existing field's mapping type to an incompatible
    type (text -> long), leaving the original mapping untouched, while a compatible additive
    schema change (adding a new field) on the same index still succeeds.
    """
    domain_name = _domain_name(ctx, "map")
    _create_minimal_domain(ctx, domain_name, engine_version="OpenSearch_2.19")
    _wait_domain_active(ctx, domain_name)

    opensearch = ctx.client("opensearch")
    index_name = "sim2real-mapping-idx"
    opensearch.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"myfield": {"type": "text"}}}},
    )
    ctx.on_cleanup(lambda: _delete_index(ctx, domain_name, index_name))

    # GetIndex's IndexSchema is a document keyed by index name, mirroring the native
    # OpenSearch mapping API response -- not the bare {"mappings": ...} shape UpdateIndex
    # accepts as input. Confirmed against real AWS: {"<index>": {"mappings": ..., "settings": ...}}.
    def _mapped_type(field: str) -> str | None:
        doc = opensearch.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
        return doc[index_name]["mappings"]["properties"].get(field, {}).get("type")

    actual = _mapped_type("myfield")
    assert actual == "text", f"expected myfield seeded as text, got {actual!r}"

    code, message = _error(
        lambda: opensearch.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"mappings": {"properties": {"myfield": {"type": "long"}}}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "mapper [myfield] cannot be changed from type [text] to [long]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the incompatible type change must not have been applied.
    actual = _mapped_type("myfield")
    assert actual == "text", f"rejected type change was applied anyway: myfield is now {actual!r}"

    # Positive control: the same UpdateIndex call, with a compatible additive change, succeeds.
    result = opensearch.update_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"otherfield": {"type": "keyword"}}}},
    )
    assert result["Status"] == "UPDATED", f"expected Status UPDATED, got {result['Status']!r}"
    actual = _mapped_type("myfield")
    assert actual == "text", f"additive update disturbed myfield: now {actual!r}"
    actual = _mapped_type("otherfield")
    assert actual == "keyword", f"additive update did not persist otherfield: got {actual!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _domain_name(ctx, tag: str) -> str:
    return f"sim2real-{tag}-{uuid.uuid4().hex[:10]}"[:28]


def _create_minimal_domain(ctx, name, *, instance_count: int = 1, instance_type: str = "t3.small.search", engine_version: str = "OpenSearch_2.11") -> None:
    opensearch = ctx.client("opensearch")
    opensearch.create_domain(
        DomainName=name,
        EngineVersion=engine_version,
        ClusterConfig={
            "InstanceType": instance_type,
            "InstanceCount": instance_count,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_domain(ctx, name))


def _delete_domain(ctx, name) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_index(ctx, domain_name, index_name) -> None:
    opensearch = ctx.client("opensearch")
    try:
        opensearch.delete_index(DomainName=domain_name, IndexName=index_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_domain_active(ctx, name, timeout_s: float = 1800.0, interval_s: float = 30.0):
    opensearch = ctx.client("opensearch")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {name} did not become active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

