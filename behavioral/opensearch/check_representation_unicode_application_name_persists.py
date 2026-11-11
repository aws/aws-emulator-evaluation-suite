"""representation-unicode-application-name-persists."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "representation-unicode-application-name-persists"
GROUP = "representation"
SERVICES = ["opensearch"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An application's name, id and arn round-trip through GetApplication, and a multi-byte
    unicode tag value set at CreateApplication comes back byte-identical from ListTags."""
    opensearch = ctx.client("opensearch")

    app_name = _app_name(ctx)
    # The application name pattern is ASCII lowercase only, so unicode goes in a tag value.
    tag_value = "Ünïcödé Ω 日本語 naïve café"


    created = opensearch.create_application(
        name=app_name, tagList=[{"Key": "sim2real-note", "Value": tag_value}]
    )
    app_id = created["id"]
    app_arn = created["arn"]
    ctx.on_cleanup(lambda: opensearch.delete_application(id=app_id))
    _wait_application_active(ctx, opensearch, app_id)

    fetched = opensearch.get_application(id=app_id)
    assert fetched["name"] == app_name, f"name did not round-trip: {fetched['name']!r} != {app_name!r}"
    assert fetched["id"] == app_id, f"id did not round-trip: {fetched['id']!r} != {app_id!r}"
    assert fetched["arn"] == app_arn, f"arn did not round-trip: {fetched['arn']!r} != {app_arn!r}"

    tags = opensearch.list_tags(ARN=app_arn)["TagList"]
    matches = [t for t in tags if t["Key"] == "sim2real-note"]
    assert len(matches) == 1, f"expected exactly one matching tag, found {matches!r}"
    got_value = matches[0]["Value"]
    assert got_value == tag_value, f"unicode tag value mangled: {got_value!r} != {tag_value!r}"
    assert got_value.encode("utf-8") == tag_value.encode("utf-8"), (
        f"utf-8 bytes diverged despite str equality: {got_value.encode('utf-8')!r} != "
        f"{tag_value.encode('utf-8')!r}"
    )

def _app_name(ctx) -> str:
    return f"sim2real-{uuid.uuid4().hex[:12]}"


def _wait_application_active(ctx, opensearch, app_id, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = opensearch.get_application(id=app_id)["status"]
        if status == "ACTIVE":
            return
        if status == "FAILED":
            raise AssertionError(f"application {app_id} entered FAILED state")
        time.sleep(3)
    raise AssertionError(f"application {app_id} never became ACTIVE within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
