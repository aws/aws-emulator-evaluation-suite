"""update-index-malformed-settings-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-index-malformed-settings-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIndex with a string settings block and with a well-formed settings change each fails with
    ValidationException and its exact message without changing the index, while a mappings change reports
    UPDATED and changes the schema.
    """
    aos = ctx.client("opensearch")
    domain_name = _compliant_domain_name(ctx, "sim2real-idxmf")
    # Registered before the create call so a failure between create and registration can
    # never leak a 24x7 cluster.
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_domain(DomainName=domain_name)))
    aos.create_domain(
        DomainName=domain_name,
        EngineVersion="OpenSearch_2.19",
        ClusterConfig={
            "InstanceType": "t3.small.search",
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        # Tagged at creation so a tag-based cleanup can find an orphaned domain.
        TagList=[{"Key": "sim2real", "Value": CHECK}],
    )

    _poll_until(
        lambda: aos.describe_domain(DomainName=domain_name)["DomainStatus"]["Processing"],
        lambda processing: processing is False,
        timeout_s=1800,
        interval_s=30,
    )

    index_name = "sim2real-idxmf-target"
    create_status = _retry_on(
        lambda: aos.create_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"settings": {"index": {"number_of_shards": 1, "number_of_replicas": 1}}},
        ),
        error_codes=("DependencyFailureException",),
        message_substrings=("not available now",),
    )["Status"]
    assert create_status == "CREATED", f"unexpected CreateIndex status {create_status}"
    ctx.on_cleanup(lambda: _safe(lambda: aos.delete_index(DomainName=domain_name, IndexName=index_name)))

    baseline = aos.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]

    malformed_code, malformed_message = _error_code_and_message(
        lambda: aos.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"settings": "not-an-object"},
        )
    )
    assert malformed_code == "ValidationException", (
        f"expected ValidationException, got {malformed_code}"
    )
    expected_malformed = "Updates to index settings is not supported."
    assert malformed_message == expected_malformed, (
        f"expected message {expected_malformed!r}, got {malformed_message!r}"
    )

    after_malformed = aos.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    assert after_malformed == baseline, "malformed UpdateIndex partially applied to the index"

    # Confirmed on real AWS: UpdateIndex rejects a well-formed settings change
    # identically to the malformed one -- it categorically refuses to touch
    # `settings`, not merely the malformed shape.
    wellformed_code, wellformed_message = _error_code_and_message(
        lambda: aos.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"settings": {"index": {"number_of_replicas": 0}}},
        )
    )
    assert wellformed_code == "ValidationException", (
        f"expected ValidationException, got {wellformed_code}"
    )
    expected_wellformed = "Updates to index settings is not supported."
    assert wellformed_message == expected_wellformed, (
        f"expected message {expected_wellformed!r}, got {wellformed_message!r}"
    )

    after_wellformed = aos.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    assert after_wellformed == baseline, "well-formed settings UpdateIndex partially applied to the index"

    # Positive control: UpdateIndex itself works -- a well-formed *mappings* change on
    # the same index succeeds and lands, proving the refusal above is specific to
    # `settings` rather than UpdateIndex being broadly non-functional.
    update_status = aos.update_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"body": {"type": "text"}}}},
    )["Status"]
    assert update_status == "UPDATED", f"unexpected UpdateIndex status {update_status}"

    updated = aos.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    assert updated != baseline, "positive-control UpdateIndex did not change the index schema"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError("expected a ClientError, call succeeded")


def _retry_on(fn, *, error_codes=(), message_substrings=(), attempts=6, delay_s=10.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if attempt < attempts - 1 and (
                code in error_codes or any(s in msg for s in message_substrings)
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")


def _compliant_domain_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(f"{prefix}-").lower()
    cleaned = "".join(c for c in raw if c.isalnum() or c == "-")
    cleaned = cleaned[:28].rstrip("-")
    if not cleaned or not cleaned[0].isalpha():
        cleaned = "d" + cleaned
    return cleaned[:28]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
