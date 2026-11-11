"""serverless-cache-description-omitted-normalizes-to-single-space."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "serverless-cache-description-omitted-normalizes-to-single-space"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Omitting Description on CreateServerlessCache normalizes to a single-space sentinel " "
    on create and describe, identical to supplying Description="" (despite the API reference
    saying an empty string is returned)."""
    ec = ctx.client("elasticache")
    name_omitted = ctx.unique_name("sim2real-scdesc-omit-")
    name_empty = ctx.unique_name("sim2real-scdesc-empty-")

    resp_omitted = ec.create_serverless_cache(
        ServerlessCacheName=name_omitted,
        Engine="redis",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        SubnetIds=ctx.network().subnet_ids[:3],
    )
    ctx.on_cleanup(lambda: _delete_serverless_cache_safe(ec, name_omitted))
    resp_empty = ec.create_serverless_cache(
        ServerlessCacheName=name_empty,
        Engine="redis",
        Description="",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        SubnetIds=ctx.network().subnet_ids[:3],
    )
    ctx.on_cleanup(lambda: _delete_serverless_cache_safe(ec, name_empty))

    assert resp_omitted["ServerlessCache"].get("Description") == " ", (
        "Description omitted at creation should normalize to the single-space sentinel ' ', got "
        f"{resp_omitted['ServerlessCache'].get('Description')!r}"
    )
    assert resp_empty["ServerlessCache"].get("Description") == " ", (
        "Description explicitly set to '' should read back as the single-space sentinel ' ', got "
        f"{resp_empty['ServerlessCache'].get('Description')!r}"
    )

    described = ec.describe_serverless_caches(ServerlessCacheName=name_omitted)["ServerlessCaches"][0]
    assert described.get("Description") == " ", (
        f"describe_serverless_caches shows Description={described.get('Description')!r}, expected ' '"
    )


def _delete_serverless_cache_safe(ec, name: str) -> None:
    """Delete the cache, retrying while it is still creating; each of the two caches gets 840 s
    so both fit the 1800 s cleanup budget."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 840.0
    while True:
        try:
            ec.delete_serverless_cache(ServerlessCacheName=name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ServerlessCacheNotFoundFault":
                return
            if code != "InvalidServerlessCacheStateFault" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
