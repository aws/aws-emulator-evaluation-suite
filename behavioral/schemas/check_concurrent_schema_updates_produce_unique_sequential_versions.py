"""concurrent-schema-updates-produce-unique-sequential-versions."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-schema-updates-produce-unique-sequential-versions"
GROUP = "concurrency"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing UpdateSchema calls never mint a duplicate version: each winner's version is unique, and losers

    are rejected with ConflictException (optimistic-concurrency on the schema's version counter) rather than
    silently clobbering another writer's version.
    """
    schemas = ctx.client("schemas")
    resource_tags = {"Environment": "test", "Team": "sim2real"}
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Tags=resource_tags)
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    schema_name = ctx.unique_name("sim2real-schemas-sch-")
    schemas.create_schema(
        RegistryName=registry,
        SchemaName=schema_name,
        Type="OpenApi3",
        Content=_openapi3_content("Widget", 0),
        Tags=resource_tags,
    )
    ctx.on_cleanup(lambda: schemas.delete_schema(RegistryName=registry, SchemaName=schema_name))

    racer_count = 5

    def _racer(idx: int):
        try:
            resp = schemas.update_schema(
                RegistryName=registry,
                SchemaName=schema_name,
                Type="OpenApi3",
                Content=_openapi3_content("Widget", idx + 1),
            )
            return ("ok", resp["SchemaVersion"])
        except ClientError as exc:
            return ("err", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    results = []
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        futures = [pool.submit(_racer, i) for i in range(racer_count)]
        for fut in as_completed(futures):
            results.append(fut.result())

    successes = [v for (kind, v) in results if kind == "ok"]
    failures = [v for (kind, v) in results if kind == "err"]

    # Every racer either won a unique version or was rejected as a stale/conflicting write — never both
    # silently overwritten and never a duplicate version minted.
    assert len(successes) + len(failures) == racer_count
    assert len(successes) >= 1, "at least one concurrent update must win"
    assert len(set(successes)) == len(successes), f"version collision under concurrency: {successes}"
    for code, message in failures:
        assert code == "ConflictException", f"unexpected rejection code for a losing racer: {code!r}"
        assert message == "The resource was modified by a concurrent request.", (
            f"unexpected rejection message for a losing racer: {message!r}"
        )

    listed = schemas.list_schema_versions(RegistryName=registry, SchemaName=schema_name)
    all_versions = {v["SchemaVersion"] for v in listed["SchemaVersions"]}
    # Version "1" (initial create) plus exactly one entry per winning racer — no gaps, no duplicates.
    expected = {"1"} | set(successes)
    assert all_versions == expected, f"expected {expected}, got {all_versions}"


def _openapi3_content(title: str, marker: int) -> str:
    return json.dumps(
        {
            "openapi": "3.0.0",
            "info": {"version": "1.0.0", "title": title},
            "paths": {},
            "components": {
                "schemas": {
                    "Event": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}, "marker": {"type": "integer", "enum": [marker]}},
                    }
                }
            },
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
