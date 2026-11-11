"""create-configuration-bundle-parallel-create-idempotency."""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-bundle-parallel-create-idempotency"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Parallel CreateConfigurationBundle calls that share the same idempotency clientToken
    and identical parameters all succeed and resolve to exactly one underlying bundle -- not
    one bundle per caller."""
    bac = ctx.client("bedrock-agentcore-control")

    bundle_name = _alnum_name(ctx, "sim2realidem")
    client_token = "sim2real" + uuid.uuid4().hex + uuid.uuid4().hex
    components = {"sim2real_component": {"configuration": {"key": "v1"}}}

    def _create():
        return bac.create_configuration_bundle(
            clientToken=client_token, bundleName=bundle_name, components=components
        )

    results = _race([_create, _create, _create])
    failures = [r for r in results if not r[0]]
    assert not failures, f"expected every replayed idempotent create to succeed, got failures: {failures}"

    bundle_ids = {r[1]["bundleId"] for r in results}
    version_ids = {r[1]["versionId"] for r in results}
    assert len(bundle_ids) == 1, f"idempotent parallel creates produced multiple bundle ids: {bundle_ids}"
    assert len(version_ids) == 1, f"idempotent parallel creates produced multiple bundle versions: {version_ids}"

    bundle_id = next(iter(bundle_ids))
    ctx.on_cleanup(lambda: bac.delete_configuration_bundle(bundleId=bundle_id))

    listed = []
    for page in bac.get_paginator("list_configuration_bundles").paginate():
        listed.extend(page["bundles"])
    matching = [b for b in listed if b["bundleId"] == bundle_id]
    assert len(matching) == 1, f"expected exactly one bundle to exist for {bundle_id}, found {matching}"


def _alnum_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


def _race(fns, timeout_s=60.0):
    results: list = [None] * len(fns)
    barrier = threading.Barrier(len(fns))

    def _wrap(i, fn):
        barrier.wait()
        try:
            return i, True, fn()
        except ClientError as exc:
            return i, False, exc.response["Error"]["Code"]

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
