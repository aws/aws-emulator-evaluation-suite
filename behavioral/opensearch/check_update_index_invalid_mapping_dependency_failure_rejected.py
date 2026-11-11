"""update-index-invalid-mapping-dependency-failure-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-index-invalid-mapping-dependency-failure-rejected"
GROUP = "negative-classes"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIndex that retypes the text field "amount" to integer fails with ValidationException and its exact
    message and leaves the mapping text, while adding a new keyword field succeeds.
    """
    client = ctx.client("opensearch")
    domain_name = _domain_name(ctx, "idx")
    _create_minimal_domain(ctx, client, domain_name)
    _wait_domain_active(ctx, client, domain_name)

    index_name = "sim2real-orders"
    create_resp = client.create_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"amount": {"type": "text"}}}},
    )
    ctx.on_cleanup(lambda: client.delete_index(DomainName=domain_name, IndexName=index_name))
    assert create_resp["Status"] == "CREATED", f"expected Status=CREATED, got {create_resp!r}"

    # GetIndex's exact IndexSchema echo shape isn't pinned in the docs (it is a Smithy `document` --
    # opaque JSON, no modeled structure), so assert on semantic content via a substring search
    # rather than a brittle exact key path.
    original_schema = client.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    dumped_original = json.dumps(original_schema)
    assert '"amount"' in dumped_original and '"text"' in dumped_original, (
        f"unexpected schema shape after CreateIndex: {original_schema!r}"
    )

    def _break() -> None:
        client.update_index(
            DomainName=domain_name,
            IndexName=index_name,
            IndexSchema={"mappings": {"properties": {"amount": {"type": "integer"}}}},
        )

    code, message = _error_code(_break)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "mapper [amount] cannot be changed from type [text] to [integer]"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the mapping for "amount" is unchanged.
    schema_after = client.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    dumped_after = json.dumps(schema_after)
    assert '"amount"' in dumped_after and '"text"' in dumped_after, (
        f"mapping for 'amount' mutated by a rejected UpdateIndex: {schema_after!r}"
    )
    assert '"integer"' not in dumped_after, (
        f"broken type change leaked into the stored schema: {schema_after!r}"
    )

    # Positive control: a non-conflicting mapping addition still succeeds.
    client.update_index(
        DomainName=domain_name,
        IndexName=index_name,
        IndexSchema={"mappings": {"properties": {"currency": {"type": "keyword"}}}},
    )
    schema_final = client.get_index(DomainName=domain_name, IndexName=index_name)["IndexSchema"]
    dumped_final = json.dumps(schema_final)
    assert '"currency"' in dumped_final and '"keyword"' in dumped_final, (
        f"additive mapping change did not persist: {schema_final!r}"
    )
    assert '"amount"' in dumped_final and '"text"' in dumped_final, (
        f"'amount' mapping lost after the additive update: {schema_final!r}"
    )


def _domain_name(ctx: Any, tag: str) -> str:
    return ctx.unique_name(f"sim2real-{tag}-")[:28].rstrip("-")


def _create_minimal_domain(ctx: Any, client: Any, domain_name: str) -> None:
    client.create_domain(
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
    ctx.on_cleanup(lambda: _delete_domain_and_wait(ctx, client, domain_name))


def _delete_domain_and_wait(ctx: Any, client: Any, domain_name: str) -> None:
    try:
        client.delete_domain(DomainName=domain_name)
    except Exception as exc:
        if _error_code_from_exc(exc) != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 1200
    while time.monotonic() < deadline:
        try:
            client.describe_domain(DomainName=domain_name)
        except Exception as exc:
            code = _error_code_from_exc(exc)
            if code == "ResourceNotFoundException":
                return
            # DescribeDomain throttles under the suite's concurrent polls: poll again.
            if code != "ThrottlingException":
                raise
        time.sleep(20)


def _wait_domain_active(ctx: Any, client: Any, domain_name: str, timeout_s: float = 1200.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            status = client.describe_domain(DomainName=domain_name)["DomainStatus"]
        except Exception as exc:  # noqa: BLE001
            # DescribeDomain throttles under the suite's concurrent polls: poll again to the deadline.
            if _error_code_from_exc(exc) != "ThrottlingException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
            continue
        last = status
        if status.get("Created") and not status.get("Processing") and status.get("Endpoint"):
            return status
        time.sleep(2)
    raise AssertionError(f"domain {domain_name} never became active: {last}")


def _error_code_from_exc(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not response:
        return None
    return response.get("Error", {}).get("Code")


def _error_code(fn) -> tuple[str | None, str | None]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None) or {}
        return _error_code_from_exc(exc), response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
