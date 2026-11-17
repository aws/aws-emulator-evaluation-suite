"""add-replication-peer-dry-run-matches-live-validation."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-replication-peer-dry-run-matches-live-validation"
GROUP = "replication"
SERVICES = ["opensearch"]

_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_ENGINE_VERSION = "OpenSearch_2.11"
# A replication peer must be in a different Region from the domain calling AddReplicationPeer;
# that is the API's own cross-region contract, not a resource this check provisions.
_PEER_REGION = "us-east-1"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_domain(os_client, name: str) -> None:
    for attempt in range(12):
        try:
            os_client.create_domain(
                DomainName=name,
                EngineVersion=_ENGINE_VERSION,
                ClusterConfig=dict(_CLUSTER_CONFIG),
                EBSOptions=dict(_EBS_OPTIONS),
            )
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in (
                "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded",
            ):
                raise
            time.sleep(6.0 * (1 + attempt) + random.uniform(0, 6.0))
    raise AssertionError("still throttled after 12 attempts")


def _delete_domain(os_client, name: str) -> None:
    try:
        os_client.delete_domain(DomainName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddReplicationPeer rejects a nonexistent peer domain with the same ValidationException,
    identical code and message, whether DryRun is true or false, and establishes no relationship
    for either call.
    """
    os_client = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(os_client, domain_name)
    ctx.on_cleanup(lambda: _delete_domain(os_client, domain_name))

    missing_peer = ctx.unique_name("sim2real-behav-os-peer-")[:28].rstrip("-")
    peer_arn = f"arn:aws:es:{_PEER_REGION}:{ctx.account}:domain/{missing_peer}"
    expected_message = f"Domain not found: {peer_arn}"

    dry_code, dry_message = _error(
        lambda: os_client.add_replication_peer(
            DomainName=domain_name, PeerDomainArn=peer_arn, DryRun=True
        )
    )
    assert dry_code == "ValidationException", f"DryRun=True: expected ValidationException, got {dry_code}: {dry_message!r}"
    assert dry_message == expected_message, f"DryRun=True: unexpected message {dry_message!r}"

    live_code, live_message = _error(
        lambda: os_client.add_replication_peer(
            DomainName=domain_name, PeerDomainArn=peer_arn, DryRun=False
        )
    )
    assert (live_code, live_message) == (dry_code, dry_message), (
        f"DryRun=False diverged from DryRun=True: {(live_code, live_message)!r} != {(dry_code, dry_message)!r}"
    )

    # Neither the dry-run nor the real attempt established a relationship: the domain still
    # reports no replication peer through an independent operation.
    own_arn = f"arn:aws:es:{ctx.region}:{ctx.account}:domain/{domain_name}"
    code, message = _error(
        lambda: os_client.remove_replication_peer(DomainName=domain_name, PeerDomainArn=peer_arn)
    )
    assert code == "ResourceNotFoundException", f"RemoveReplicationPeer after both attempts: expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == f"Domain is not replicating: {own_arn}", f"RemoveReplicationPeer after both attempts: unexpected message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
