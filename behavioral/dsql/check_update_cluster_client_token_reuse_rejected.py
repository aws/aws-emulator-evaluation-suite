"""update-cluster-client-token-reuse-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-cluster-client-token-reuse-rejected"
GROUP = "idempotency"
SERVICES = ["dsql"]

_ACTIVE_TIMEOUT_S = 600.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCluster honours its clientToken: a replay with the same parameters answers for the same
    cluster, the same token with different parameters fails with ConflictException and AWS's exact
    message and changes nothing, and a fresh token applies the change."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real": CHECK, "Name": ctx.unique_name("sim2real-behav-dsql-")},
    )
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _unprotect_and_delete(dsql, identifier))
    _wait_settled(dsql, identifier)

    token = str(uuid.uuid4())
    first = dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=True, clientToken=token)
    assert first["identifier"] == identifier, f"UpdateCluster answered for {first['identifier']!r}"
    replay = dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=True, clientToken=token)
    assert (replay["identifier"], replay["arn"]) == (identifier, created["arn"]), (
        "replaying the same clientToken and parameters answered for a different cluster"
    )

    code, message = _error(lambda: dsql.update_cluster(
        identifier=identifier, deletionProtectionEnabled=False, clientToken=token))
    assert code == "ConflictException", f"reusing a clientToken with other parameters answered {code!r}"
    assert message == "Requests using a client token should supply identical request parameters", (
        f"the token-reuse refusal said {message!r}"
    )

    settled = _wait_settled(dsql, identifier)
    assert settled["deletionProtectionEnabled"] is True, (
        f"after the refused reuse the cluster settled with deletionProtectionEnabled="
        f"{settled['deletionProtectionEnabled']!r}, expected the first request's True"
    )

    dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False, clientToken=str(uuid.uuid4()))
    settled = _wait_settled(dsql, identifier)
    assert settled["deletionProtectionEnabled"] is False, (
        "an update under a fresh clientToken did not turn deletion protection off"
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_settled(dsql, identifier: str) -> dict:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        cluster = dsql.get_cluster(identifier=identifier)
        if cluster["status"] in ("ACTIVE", "FAILED") or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert cluster["status"] == "ACTIVE", f"cluster settled in {cluster['status']!r}, not ACTIVE"
    return cluster


def _unprotect_and_delete(dsql, identifier: str) -> None:
    try:
        cluster = _wait_settled(dsql, identifier)
        if cluster["deletionProtectionEnabled"]:
            dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
            _wait_settled(dsql, identifier)
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
