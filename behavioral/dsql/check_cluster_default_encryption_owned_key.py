"""cluster-default-encryption-owned-key."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cluster-default-encryption-owned-key"
GROUP = "state"
SERVICES = ["dsql"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster created without a kmsEncryptionKey is encrypted with an AWS owned key by
    default: once the cluster is ACTIVE, encryptionDetails.encryptionStatus is ENABLED (not
    merely ENABLING) and no kmsKeyArn is reported."""
    dsql = ctx.client("dsql")
    created = dsql.create_cluster(deletionProtectionEnabled=False)
    identifier = created["identifier"]
    ctx.on_cleanup(lambda: _best_effort_delete(dsql, identifier))

    final = _wait_for_status(dsql, identifier, {"ACTIVE"}, timeout_s=180)
    encryption = final["encryptionDetails"]
    assert encryption["encryptionType"] == "AWS_OWNED_KMS_KEY", encryption
    assert encryption["encryptionStatus"] == "ENABLED", encryption
    assert encryption.get("kmsKeyArn") is None, encryption


def _wait_for_status(dsql, identifier, target_statuses, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = dsql.get_cluster(identifier=identifier)
        if last["status"] in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"cluster never reached {target_statuses}, last={last}")


def _best_effort_delete(dsql, identifier):
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
