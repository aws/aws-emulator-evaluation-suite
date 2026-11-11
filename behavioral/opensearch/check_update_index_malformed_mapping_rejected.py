"""update-index-malformed-mapping-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-index-malformed-mapping-rejected"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIndex with "properties" given as a list fails with InternalException and its exact message and
    leaves the mapping unchanged, while a well-formed UpdateIndex reports UPDATED and adds its field.
    """
    opensearch = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-idx")[:28].rstrip("-")

    opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_domain_ignore_missing(opensearch, domain_name))
    _wait_domain_created(opensearch, domain_name)

    index_name = "sim2real-idx"
    opensearch.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"title": {"type": "text"}}}},
    )
    ctx.on_cleanup(lambda: _delete_index_ignore_missing(opensearch, domain_name, index_name))

    malformed_schema = {"mappings": {"properties": ["not", "an", "object"]}}
    code, message = _error_detail(
        lambda: opensearch.update_index(
            DomainName=domain_name, IndexName=index_name, IndexSchema=malformed_schema
        )
    )
    assert code == "InternalException", f"expected InternalException, got {code!r}"
    expected = "Internal service error. Please retry."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the original mapping is unchanged.
    schema_after_reject = opensearch.get_index(DomainName=domain_name, IndexName=index_name)[
        "IndexSchema"
    ]
    props = _mapping_properties(schema_after_reject, index_name)
    assert props.get("title", {}).get("type") == "text", (
        f"malformed UpdateIndex corrupted the mapping: {schema_after_reject!r}"
    )
    assert "body" not in props, (
        f"malformed UpdateIndex added a field it should have rejected: {props!r}"
    )

    # Positive control: a well-formed UpdateIndex on the same index succeeds.
    valid_schema = {
        "mappings": {
            "properties": {"title": {"type": "text"}, "body": {"type": "text"}}
        }
    }
    resp = opensearch.update_index(
        DomainName=domain_name, IndexName=index_name, IndexSchema=valid_schema
    )
    assert resp["Status"] == "UPDATED", f"expected Status=UPDATED, got {resp!r}"
    schema_after_valid = opensearch.get_index(DomainName=domain_name, IndexName=index_name)[
        "IndexSchema"
    ]
    props_after = _mapping_properties(schema_after_valid, index_name)
    assert props_after.get("body", {}).get("type") == "text", (
        f"valid UpdateIndex did not persist: {schema_after_valid!r}"
    )


def _mapping_properties(schema, index_name):
    # GetIndex's exact IndexSchema echo shape isn't pinned in the docs; real AWS was observed keying
    # the echo by index name, one level above "mappings".
    node = schema.get(index_name, schema) if isinstance(schema, dict) else schema
    return node.get("mappings", {}).get("properties", {})


def _error_detail(fn):
    """(code, message) of the rejection; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_domain_created(opensearch, domain_name, timeout_s=1500.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        last = status
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain_name} did not become ready within {timeout_s}s: {last!r}")


def _delete_domain_ignore_missing(opensearch, domain_name):
    from botocore.exceptions import ClientError

    try:
        opensearch.delete_domain(DomainName=domain_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_index_ignore_missing(opensearch, domain_name, index_name):
    from botocore.exceptions import ClientError

    try:
        opensearch.delete_index(DomainName=domain_name, IndexName=index_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
