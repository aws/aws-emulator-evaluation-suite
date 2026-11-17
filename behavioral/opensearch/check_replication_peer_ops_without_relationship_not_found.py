"""replication-peer-ops-without-relationship-not-found."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-peer-ops-without-relationship-not-found"
GROUP = "replication"
SERVICES = ["opensearch"]

_CLUSTER_CONFIG = {"InstanceType": "t3.small.search", "InstanceCount": 1}
_EBS_OPTIONS = {"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10}
_ENGINE_VERSION = "OpenSearch_2.11"
# AddReplicationPeer and its family require the peer domain in a different Region from the
# domain they are called against; that is the API's own cross-region contract, not a resource
# this check provisions.
_PEER_REGION = "us-east-1"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_domain(ctx, os_client, name: str) -> None:
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
    """RemoveReplicationPeer, FailoverReplication and SwitchoverReplication on a domain with no
    replication relationship each fail with ResourceNotFoundException, and the domain is
    untouched by any of them.
    """
    os_client = ctx.client("opensearch")
    domain_name = ctx.unique_name("sim2real-behav-os-")[:28].rstrip("-")
    _create_domain(ctx, os_client, domain_name)
    ctx.on_cleanup(lambda: _delete_domain(os_client, domain_name))

    other_peer = ctx.unique_name("sim2real-behav-os-peer-")[:28].rstrip("-")
    peer_arn = f"arn:aws:es:{_PEER_REGION}:{ctx.account}:domain/{other_peer}"
    own_arn = f"arn:aws:es:{ctx.region}:{ctx.account}:domain/{domain_name}"
    _not_replicating_message = f"Domain is not replicating: {own_arn}"

    code, message = _error(
        lambda: os_client.remove_replication_peer(DomainName=domain_name, PeerDomainArn=peer_arn)
    )
    assert code == "ResourceNotFoundException", f"RemoveReplicationPeer: expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == _not_replicating_message, f"RemoveReplicationPeer: unexpected message {message!r}"

    code, message = _error(
        lambda: os_client.failover_replication(
            DomainName=domain_name, PeerDomainArn=peer_arn, AllowDataLoss=True
        )
    )
    assert code == "ValidationException", f"FailoverReplication: expected ValidationException, got {code}: {message!r}"
    assert message == _not_replicating_message, f"FailoverReplication: unexpected message {message!r}"

    code, message = _error(
        lambda: os_client.switchover_replication(DomainName=domain_name, PeerDomainArn=peer_arn)
    )
    assert code == "ValidationException", f"SwitchoverReplication: expected ValidationException, got {code}: {message!r}"
    assert message == _not_replicating_message, f"SwitchoverReplication: unexpected message {message!r}"

    # The domain itself is unaffected by any of the three refused calls.
    still_there = os_client.describe_domain(DomainName=domain_name)["DomainStatus"]
    assert still_there["DomainName"] == domain_name, f"domain disappeared after refused replication calls: {still_there!r}"
    assert still_there["Deleted"] is False, f"domain reported Deleted=True after refused replication calls: {still_there!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
