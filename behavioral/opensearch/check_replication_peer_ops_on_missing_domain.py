"""replication-peer-ops-on-missing-domain."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-peer-ops-on-missing-domain"
GROUP = "domain"
SERVICES = ["opensearch"]

# AddReplicationPeer and its siblings require PeerDomainArn to name a domain in a different AWS
# Region from the one the call targets; a fixed second region isolates the missing-local-domain
# refusal this check is about from that unrelated same-region rule.
_PEER_REGION = "us-east-1"


def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name("sim2real-behav-os-rep-")[:28].rstrip("-")


def _peer_arn(ctx, peer_name: str) -> str:
    region = _PEER_REGION if ctx.region != _PEER_REGION else "us-west-2"
    return f"arn:aws:es:{region}:{ctx.account}:domain/{peer_name}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddReplicationPeer rejects an unknown local domain with ValidationException;
    FailoverReplication and SwitchoverReplication reject it with ResourceNotFoundException; all
    three name the domain's own ARN, and RemoveReplicationPeer names it not replicating instead."""
    os_client = ctx.client("opensearch")
    missing = _missing_domain_name(ctx)
    peer_arn = _peer_arn(ctx, _missing_domain_name(ctx))

    expected_message = f"Domain not found: arn:aws:es:{ctx.region}:{ctx.account}:domain/{missing}"

    code, message = _error(
        lambda: os_client.add_replication_peer(DomainName=missing, PeerDomainArn=peer_arn)
    )
    assert code == "ValidationException", f"AddReplicationPeer: got {code} / {message!r}"
    assert message == expected_message, f"AddReplicationPeer: got message {message!r}"

    not_replicating = f"Domain is not replicating: arn:aws:es:{ctx.region}:{ctx.account}:domain/{missing}"

    code, message = _error(
        lambda: os_client.remove_replication_peer(DomainName=missing, PeerDomainArn=peer_arn)
    )
    assert code == "ResourceNotFoundException", f"RemoveReplicationPeer: got {code} / {message!r}"
    assert message == not_replicating, f"RemoveReplicationPeer: got message {message!r}"

    code, message = _error(
        lambda: os_client.failover_replication(
            DomainName=missing, PeerDomainArn=peer_arn, AllowDataLoss=True
        )
    )
    assert code == "ResourceNotFoundException", f"FailoverReplication: got {code} / {message!r}"
    assert message == expected_message, f"FailoverReplication: got message {message!r}"

    code, message = _error(
        lambda: os_client.switchover_replication(DomainName=missing, PeerDomainArn=peer_arn)
    )
    assert code == "ResourceNotFoundException", f"SwitchoverReplication: got {code} / {message!r}"
    assert message == expected_message, f"SwitchoverReplication: got message {message!r}"


def _error(fn) -> tuple:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"a missing domain must be rejected, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
