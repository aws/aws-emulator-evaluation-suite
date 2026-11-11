"""inbound-connection-lifecycle."""
from __future__ import annotations

import random
import secrets
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "inbound-connection-lifecycle"
GROUP = 'connections'
SERVICES = ['opensearch']

ENGINE_VERSION = 'OpenSearch_2.11'
_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Cross-cluster search prerequisites on both peers: a supported instance type (not T2/T3),
# node-to-node encryption, fine-grained access control (which itself needs encryption at rest
# and EnforceHTTPS), and public (non-VPC) domains. A peer missing any of them leaves the outbound
# connection in VALIDATION_FAILED, and no inbound connection is ever created.
INSTANCE_TYPE = 'm5.large.search'


def _ccs_prereq_kwargs() -> dict:
    """CreateDomain kwargs that make a domain eligible to be a cross-cluster peer.

    A function, not a constant, because the FGAC admin password is generated per domain.
    """
    return {
        "NodeToNodeEncryptionOptions": {"Enabled": True},
        "EncryptionAtRestOptions": {"Enabled": True},
        "DomainEndpointOptions": {"EnforceHTTPS": True},
        "AdvancedSecurityOptions": {
            "Enabled": True,
            "InternalUserDatabaseEnabled": True,
            # The internal user database is the only FGAC form needing no pre-existing IAM
            # principal; AWS refuses to enable FGAC without an admin user. Never logged.
            # 8-128 chars with an upper, a lower, a digit and a special character.
            "MasterUserOptions": {
                "MasterUserName": "sim2real-master",
                "MasterUserPassword": f"Sim2Real!{secrets.token_urlsafe(18)}Aa1",
            },
        },
    }


# Marks a resource that was accepted but never converged to its ready state.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _never_ready(msg: str):
    """The error for a resource that never reached its ready state.

    Returns the exception rather than raising it, so a call site keeps its ``from exc`` chaining.
    """
    return AssertionError(f"{STATE_MARKER}: {msg}")


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
        TagList=[{"Key": "sim2real", "Value": CHECK}],
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
    return resp["DomainStatus"]


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """Poll until the domain is Created with a published Endpoint and no change running
    (Processing=False alone can flip before its state machine settles); 10-20 min on AWS."""
    budget = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + budget
    last = None
    while True:
        last = osc.describe_domain(DomainName=domain_name)["DomainStatus"]
        if (last.get("Processing") is False and last.get("Created") is True
                and last.get("UpgradeProcessing") is not True
                and last.get("DomainProcessingStatus", "Active") == "Active"
                and last.get("Endpoint")):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    if _budget_spent(ctx):
        raise TimeoutError(f"domain {domain_name} to become Active: the run budget ended first; not graded")
    raise _never_ready(
        f"domain {domain_name} never became Active within {budget}s")


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


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition", ctx=None):
    """Poll ``probe`` until ``predicate``.

    On exhaustion raise via :func:`_never_ready` when ``ctx`` is given, else a plain AssertionError.
    """
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            break
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    msg = f"{description} not met within {timeout_s}s. Last result: {last!r}"
    if ctx is None:
        raise AssertionError(msg)
    raise _never_ready(msg)


def _error(fn) -> tuple:
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two cross-cluster connections between one domain pair, one is accepted (ACTIVE) and one
    rejected (REJECTED); DescribeInboundConnections reflects both, DeleteInboundConnection removes
    the accepted one, and accepting an unknown connection id is ResourceNotFoundException."""
    osc = ctx.client("opensearch")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    local = ctx.unique_name("sim2real-behav-os-loc-")[:28].rstrip("-")
    remote = ctx.unique_name("sim2real-behav-os-rem-")[:28].rstrip("-")
    _create_domain(ctx, osc, local)
    _create_domain(ctx, osc, remote)
    _wait_domain_active(ctx, osc, local)
    # Same budget as `local`: both domains provision concurrently.
    _wait_domain_active(ctx, osc, remote)
    # Cross-cluster validation needs both peers Active at once; `local` can re-enter processing
    # while `remote` finishes, so confirm it again (returns at once when it is still Active).
    _wait_domain_active(ctx, osc, local)

    def open_connection(conn_local: str, conn_remote: str) -> str:
        def _attempt() -> dict:
            alias = ("conn" + uuid.uuid4().hex)[:20]
            return osc.create_outbound_connection(
                LocalDomainInfo={
                    "AWSDomainInformation": {
                        "OwnerId": account_id, "DomainName": conn_local, "Region": region
                    }
                },
                RemoteDomainInfo={
                    "AWSDomainInformation": {
                        "OwnerId": account_id, "DomainName": conn_remote, "Region": region
                    }
                },
                ConnectionAlias=alias,
                ConnectionMode="DIRECT",
            )

        # ConnectionAlias collisions have been observed even with a fresh random
        # suffix each call; regenerate and retry rather than assume uniqueness.
        created = _retry_on(
            _attempt, error_codes=("ResourceAlreadyExistsException",), attempts=4, delay_s=2.0
        )
        cid = created["ConnectionId"]
        ctx.on_cleanup(lambda _c=cid: osc.delete_outbound_connection(ConnectionId=_c))
        return cid

    # ResourceAlreadyExistsException here is keyed on the (local, remote, mode)
    # domain-pair tuple, not just the alias -- reverse local/remote for the
    # second connection so it's a distinct pair.
    accept_cid = open_connection(local, remote)
    reject_cid = open_connection(remote, local)

    def _inbound(cid):
        conns = osc.describe_inbound_connections(
            Filters=[{"Name": "connection-id", "Values": [cid]}]
        ).get("Connections", [])
        return conns[0] if conns else None

    def _outbound(cid):
        conns = osc.describe_outbound_connections(
            Filters=[{"Name": "connection-id", "Values": [cid]}]
        ).get("Connections", [])
        return conns[0] if conns else None

    # Check outbound validation first: an outbound connection that fails validation never
    # produces an inbound connection, so the inbound poll would only time out.
    for cid in (accept_cid, reject_cid):
        validated = _poll_until(
            lambda _c=cid: _outbound(_c),
            lambda c: c is not None
            and c.get("ConnectionStatus", {}).get("StatusCode")
            in ("PENDING_ACCEPTANCE", "APPROVED", "ACTIVE", "VALIDATION_FAILED"),
            timeout_s=600,
            description=f"outbound connection {cid} validated",
            ctx=ctx,
        )
        assert validated["ConnectionStatus"]["StatusCode"] != "VALIDATION_FAILED", (
            f"cross-cluster validation FAILED for outbound {cid}, so no inbound connection can "
            f"exist: {validated['ConnectionStatus']}"
        )

    pending = _poll_until(
        lambda: _inbound(accept_cid),
        lambda c: c is not None
        and c.get("ConnectionStatus", {}).get("StatusCode")
        in ("PENDING_ACCEPTANCE", "APPROVED", "PROVISIONING", "ACTIVE"),
        timeout_s=600,
        description=f"inbound connection {accept_cid} pending",
        ctx=ctx,
    )
    assert pending is not None

    described = osc.describe_inbound_connections(
        Filters=[{"Name": "connection-id", "Values": [accept_cid, reject_cid]}]
    )["Connections"]
    assert {c["ConnectionId"] for c in described} >= {accept_cid, reject_cid}

    osc.accept_inbound_connection(ConnectionId=accept_cid)
    accepted = _poll_until(
        lambda: _inbound(accept_cid),
        lambda c: c is not None
        and c.get("ConnectionStatus", {}).get("StatusCode") in ("ACTIVE", "VALIDATION_FAILED"),
        timeout_s=600,
        description=f"inbound connection {accept_cid} accepted",
        ctx=ctx,
    )
    assert accepted is not None and accepted["ConnectionStatus"]["StatusCode"] == "ACTIVE"

    osc.reject_inbound_connection(ConnectionId=reject_cid)
    rejected = _poll_until(
        lambda: _inbound(reject_cid),
        lambda c: c is not None and c.get("ConnectionStatus", {}).get("StatusCode") == "REJECTED",
        timeout_s=300,
        description=f"inbound connection {reject_cid} rejected",
        ctx=ctx,
    )
    assert rejected is not None and rejected["ConnectionStatus"]["StatusCode"] == "REJECTED"

    osc.delete_inbound_connection(ConnectionId=accept_cid)
    deleted = _poll_until(
        lambda: _inbound(accept_cid),
        lambda c: c is None or c.get("ConnectionStatus", {}).get("StatusCode") == "DELETED",
        timeout_s=600,
        description=f"inbound connection {accept_cid} deleted",
        ctx=ctx,
    )
    assert deleted is None or deleted["ConnectionStatus"]["StatusCode"] == "DELETED"

    # A connection id that never existed must be rejected, not silently no-op.
    code, message = _error(lambda: osc.accept_inbound_connection(ConnectionId="cid-doesnotexist"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Connection ID cid-doesnotexist does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
