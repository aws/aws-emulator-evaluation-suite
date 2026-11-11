"""overly-permissive-update-index-invalid-mapping-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "overly-permissive-update-index-invalid-mapping-rejected"
GROUP = "overly-permissive"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIndex must reject a mapping that redefines an existing field's type
    incompatibly (integer -> text), leaving the stored schema unchanged, while a
    compatible additive mapping change on the same index still succeeds."""
    opensearch = ctx.client("opensearch")
    domain_name = _domain_name(ctx)

    opensearch.create_domain(
        DomainName=domain_name,
        ClusterConfig={"InstanceType": "t3.small.search", "InstanceCount": 1},
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        TagList=[{"Key": "sim2real", "Value": domain_name}],
    )
    ctx.on_cleanup(lambda: opensearch.delete_domain(DomainName=domain_name))
    _wait_domain_active(ctx, opensearch, domain_name)

    index_name = "sim2real-widgets"
    _create_index_when_ready(
        opensearch,
        domain_name,
        index_name,
        {"mappings": {"properties": {"age": {"type": "integer"}}}},
    )
    ctx.on_cleanup(
        lambda: opensearch.delete_index(DomainName=domain_name, IndexName=index_name)
    )

    # Positive control: an additive, compatible mapping change succeeds.
    ok_resp = opensearch.update_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={
            "mappings": {
                "properties": {
                    "age": {"type": "integer"},
                    "label": {"type": "keyword"},
                }
            }
        },
    )
    assert ok_resp["Status"] == "UPDATED", f"expected additive update to succeed, got {ok_resp['Status']!r}"

    # Negative: redefining "age" from integer to text is a breaking mapping change.
    code, message = _error(
        lambda: opensearch.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"mappings": {"properties": {"age": {"type": "text"}}}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "mapper [age] cannot be changed from type [integer] to [text]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the field is still an integer, not silently switched to text.
    # GetIndex nests the mapping under the index name, mirroring the OpenSearch REST
    # API's `GET /<index>/_mapping` shape: {"<index>": {"mappings": {...}, ...}}.
    schema = opensearch.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    properties = schema[index_name]["mappings"]["properties"]
    age_type = properties["age"]["type"]
    assert age_type == "integer", f"expected rejected type change to leave 'age' as integer, got {age_type!r}"
    label_type = properties["label"]["type"]
    assert label_type == "keyword", f"expected the earlier additive 'label' field to persist as keyword, got {label_type!r}"


def _domain_name(ctx) -> str:
    import uuid

    return f"sim2real-{uuid.uuid4().hex[:12]}"


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_index_when_ready(opensearch, domain_name, index_name, index_schema, timeout_s: float = 600.0, interval_s: float = 20.0):
    """A domain that is Created and not Processing can still refuse CreateIndex with
    DependencyFailureException for a while — the data-plane cluster settles after the control
    plane reports Active. Retry on that specific code only, never on the assertion under test."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return opensearch.create_index(
                DomainName=domain_name, IndexName=index_name, IndexSchema=index_schema
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyFailureException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _wait_domain_active(ctx, opensearch, domain_name, timeout_s: float = 1800.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.describe_domain(DomainName=domain_name)["DomainStatus"]
        if status.get("Created") and not status.get("Processing"):
            return
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} never became active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
