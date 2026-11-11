"""type-create-active-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "type-create-active-transition"
GROUP = "state-machine"
SERVICES = ["keyspaces"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateType transitions Type.status from CREATING to ACTIVE, observable via GetType."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    type_name = _kname(ctx, "sim2real_behav_type")

    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": "behav"}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_keyspace(keyspaceName=ks_name)))

    fields = [{"name": "street", "type": "text"}, {"name": "city", "type": "text"}]
    _create_type_when_ready(ctx, kc, ks_name, type_name, fields)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_type(keyspaceName=ks_name, typeName=type_name)))

    statuses_seen = []
    deadline = time.monotonic() + 120.0
    final_status = None
    from botocore.exceptions import ClientError
    while time.monotonic() < deadline:
        try:
            final_status = kc.get_type(keyspaceName=ks_name, typeName=type_name)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(2.0)
            continue
        statuses_seen.append(final_status)
        if final_status == "ACTIVE":
            break
        time.sleep(2.0)
    assert final_status == "ACTIVE", f"type never reached ACTIVE, last statuses observed: {statuses_seen[-5:]}"
    assert all(s in ("CREATING", "ACTIVE") for s in statuses_seen), (
        f"type transition observed a status outside {{CREATING, ACTIVE}}: {statuses_seen}")

    got = kc.get_type(keyspaceName=ks_name, typeName=type_name)
    assert got["fieldDefinitions"] == fields, got["fieldDefinitions"]


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _ignore_not_found(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_type_when_ready(ctx, kc, ks_name: str, type_name: str, fields: list, timeout_s: float = 90.0) -> None:
    """CreateType right after CreateKeyspace can transiently 404 until the keyspace is
    visible; retry only that specific transient condition."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.create_type(keyspaceName=ks_name, typeName=type_name, fieldDefinitions=fields)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
