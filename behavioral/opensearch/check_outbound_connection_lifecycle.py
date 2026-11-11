"""outbound-connection-lifecycle."""
from __future__ import annotations

import random
import secrets
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "outbound-connection-lifecycle"
GROUP = 'connections'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Cross-cluster search requires a non-T2/T3 instance type, node-to-node encryption, fine-grained
# access control (with encryption at rest and EnforceHTTPS), and public or peered domains; a peer
# missing any of them settles at VALIDATION_FAILED.
#
#   * instance type -- cross-cluster search does not support T2/T3. m5.large.search is supported,
#     and also satisfies the instance-type restriction on encryption at rest below.
#   * encryption in transit -- AWS reports "The domain does not have encryption in transit
#     enabled." Node-to-node encryption is OFF by default, so a minimal domain can never be a
#     cross-cluster peer.
#   * fine-grained access control -- AWS reports "The domain does not have fine-grained access
#     control enabled." FGAC is off by default too.
#   * encryption at rest + EnforceHTTPS -- co-requisites of FGAC (it cannot be enabled without
#     them).
#
# The domains are PUBLIC, since VPC peers additionally require VPC peering or Transit Gateway
# between them.
INSTANCE_TYPE = 'm5.large.search'


def _ccs_prereq_kwargs() -> dict:
    """CreateDomain kwargs that make a domain eligible to be a cross-cluster peer.

    A function, not a constant, because the FGAC admin password must be generated per domain.
    """
    return {
        "NodeToNodeEncryptionOptions": {"Enabled": True},
        "EncryptionAtRestOptions": {"Enabled": True},
        "DomainEndpointOptions": {"EnforceHTTPS": True},
        "AdvancedSecurityOptions": {
            "Enabled": True,
            "InternalUserDatabaseEnabled": True,
            # The internal user database is the only form of FGAC that needs no pre-existing IAM
            # principal. Nothing here ever authenticates as this user: the credential exists only
            # because AWS refuses to enable FGAC without one. Generated per domain, never logged.
            # 8-128 chars with an upper, a lower, a digit and a special character.
            "MasterUserOptions": {
                "MasterUserName": "sim2real-master",
                "MasterUserPassword": f"Sim2Real!{secrets.token_urlsafe(18)}Aa1",
            },
        },
    }


def _never_ready(msg: str) -> AssertionError:
    """The error for a resource that never converged; returned to keep ``from exc`` chaining."""
    return AssertionError(msg)


def _create_domain(ctx, osc, domain_name) -> dict:
    kwargs = dict(
        DomainName=domain_name,
        EngineVersion=ENGINE_VERSION,
        ClusterConfig={
            "InstanceType": INSTANCE_TYPE,
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp2", "VolumeSize": 10},
        **_ccs_prereq_kwargs(),
    )
    for _attempt in range(12):
        try:
            resp = osc.create_domain(**kwargs)
            break
        except ClientError as _e:
            if _e.response.get("Error", {}).get("Code") not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (1 + _attempt) + random.uniform(0, 6.0))
    else:
        raise AssertionError("still throttled after 12 attempts")
    ctx.on_cleanup(lambda: osc.delete_domain(DomainName=domain_name))
    domain = resp["DomainStatus"]
    osc.add_tags(ARN=domain["ARN"], TagList=[{"Key": "sim2real-behav", "Value": CHECK}])
    return domain


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until Processing=False and Created=True; a domain needs 10-20 min to go Active."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if last.get("Processing") is False and last.get("Created") is True:
            return last
        time.sleep(2)
    raise _never_ready(
        f"domain {domain_name} never became Active within {budget}s",
    )


def _retry_on(fn, *, error_codes=(), message_substrings=(), attempts=6, delay_s=10.0):
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = exc.response.get("Error", {}).get("Message", "")
            if attempt < attempts - 1 and (
                code in error_codes or any(s in msg for s in message_substrings)
            ):
                last_exc = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=6.0, description="condition", ctx=None):
    """Poll ``probe`` until ``predicate``; on exhaustion fail naming the last result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    msg = f"{description} not met within {timeout_s}s. Last result: {last!r}"
    raise _never_ready(msg)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOutboundConnection starts PENDING_ACCEPTANCE, visible via
    DescribeOutboundConnections; DeleteOutboundConnection drives it through
    DELETING to fully gone."""
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    local = ctx.unique_name("sim2real-behav-os-loc-")[:28].rstrip("-")
    remote = ctx.unique_name("sim2real-behav-os-rem-")[:28].rstrip("-")
    _create_domain(ctx, osc, local)
    _create_domain(ctx, osc, remote)
    _wait_domain_active(ctx, osc, local)
    # Same budget as `local`: both domains were created above and provision concurrently.
    _wait_domain_active(ctx, osc, remote)

    def _attempt():
        alias = ("alias" + uuid.uuid4().hex)[:20]
        resp = osc.create_outbound_connection(
            LocalDomainInfo={
                "AWSDomainInformation": {
                    "OwnerId": account_id, "DomainName": local, "Region": region
                }
            },
            RemoteDomainInfo={
                "AWSDomainInformation": {
                    "OwnerId": account_id, "DomainName": remote, "Region": region
                }
            },
            ConnectionAlias=alias,
            ConnectionMode="DIRECT",
        )
        return resp, alias

    # ConnectionAlias collisions have been observed even with a fresh random
    # suffix each call; regenerate and retry rather than assume uniqueness.
    created, alias = _retry_on(
        _attempt, error_codes=("ResourceAlreadyExistsException",), attempts=4, delay_s=2.0
    )
    connection_id = created["ConnectionId"]
    ctx.on_cleanup(lambda: osc.delete_outbound_connection(ConnectionId=connection_id))
    assert created["ConnectionAlias"] == alias, (
        f"CreateOutboundConnection echoed alias {created['ConnectionAlias']!r}, expected {alias!r}"
    )

    described = osc.describe_outbound_connections(
        Filters=[{"Name": "connection-id", "Values": [connection_id]}]
    )["Connections"]
    assert described and described[0]["ConnectionId"] == connection_id, (
        f"DescribeOutboundConnections did not return {connection_id} via connection-id filter: "
        f"{described!r}"
    )

    def _outbound(cid):
        conns = osc.describe_outbound_connections(
            Filters=[{"Name": "connection-id", "Values": [cid]}]
        ).get("Connections", [])
        return conns[0] if conns else None

    # DeleteOutboundConnection is rejected while the connection is still
    # VALIDATING/PROVISIONING -- wait for it to reach a stable state first.
    #
    # VALIDATION_FAILED is terminal, so it ends the poll, and the assertion below rejects it.
    stable = _poll_until(
        lambda: _outbound(connection_id),
        lambda c: c is not None
        and c.get("ConnectionStatus", {}).get("StatusCode")
        in ("PENDING_ACCEPTANCE", "APPROVED", "ACTIVE", "VALIDATION_FAILED"),
        timeout_s=600,
        description=f"outbound connection {connection_id} stable",
        ctx=ctx,
    )
    assert stable["ConnectionStatus"]["StatusCode"] != "VALIDATION_FAILED", (
        f"outbound connection {connection_id} failed cross-cluster validation, so the DELETE "
        f"below would grade nothing: {stable['ConnectionStatus']}"
    )

    osc.delete_outbound_connection(ConnectionId=connection_id)
    gone = _poll_until(
        lambda: _outbound(connection_id),
        lambda c: c is None or c.get("ConnectionStatus", {}).get("StatusCode") == "DELETED",
        timeout_s=300,
        description=f"outbound connection {connection_id} deleted",
        ctx=ctx,
    )
    assert gone is None or gone["ConnectionStatus"]["StatusCode"] == "DELETED", (
        f"outbound connection {connection_id} settled at "
        f"{gone['ConnectionStatus']!r} instead of DELETED after DeleteOutboundConnection"
    )

    described_after = osc.describe_outbound_connections(
        Filters=[{"Name": "connection-id", "Values": [connection_id]}]
    )["Connections"]
    assert not described_after or described_after[0]["ConnectionStatus"]["StatusCode"] == "DELETED", (
        f"independent post-delete read still shows outbound connection {connection_id} as "
        f"{described_after[0]['ConnectionStatus']!r}"
    )

    # Measured on real AWS: DeleteOutboundConnection on an already-deleted connection id is a
    # clean idempotent no-op (no ResourceNotFoundException), so the invariant to hold is
    # "does not resurrect or error", not "rejects".
    try:
        osc.delete_outbound_connection(ConnectionId=connection_id)
        second_delete_code = None
    except ClientError as _e:
        second_delete_code = _e.response.get("Error", {}).get("Code")
    assert second_delete_code is None, (
        f"deleting the already-deleted outbound connection {connection_id} a second time "
        f"raised {second_delete_code!r}, expected an idempotent no-op success"
    )
    still_gone = _outbound(connection_id)
    assert still_gone is None or still_gone["ConnectionStatus"]["StatusCode"] == "DELETED", (
        f"a double-deleted outbound connection {connection_id} must not be resurrected, got "
        f"{still_gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
