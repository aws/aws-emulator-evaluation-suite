"""inbound-outbound-connection-accept-reject-lifecycle."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "inbound-outbound-connection-accept-reject-lifecycle"
GROUP = "state-machine"
SERVICES = ["opensearch"]

# Cross-cluster search PREREQUISITES on the peer domains. A domain that doesn't meet them
# (t3.small.search, no node-to-node encryption, no FGAC) is accepted by CreateOutboundConnection and
# then settles to VALIDATION_FAILED -- and a failed-validation outbound connection never
# materializes an inbound connection at all, so this check's accept/reject state machine could never
# be exercised.
INSTANCE_TYPE = "m5.large.search"


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
            "MasterUserOptions": {
                "MasterUserName": "sim2real-master",
                "MasterUserPassword": f"Sim2Real!{secrets.token_urlsafe(18)}Aa1",
            },
        },
    }


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Inbound cross-cluster connection requests transition through accept/reject,
    and outbound connections through create/delete, disappearing (or going terminal)
    in the describe listings once resolved."""
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    local_name = _create_minimal_domain(ctx)
    remote_name = _create_minimal_domain(ctx)
    _wait_domains_active(ctx, [local_name, remote_name], timeout_s=2400.0)

    # --- Connection #1: accepted ---
    # AWSDomainInformation.OwnerId is not documented as required, but real AWS rejects
    # CreateOutboundConnection with ValidationException ("Value null at
    # '...awsDomainInformation.ownerId'") when it's omitted, even for a same-account
    # connection -- it must always be supplied explicitly.
    alias_accept = ctx.unique_name("sim2realCxA")
    conn1 = aos.create_outbound_connection(
        ConnectionAlias=alias_accept,
        LocalDomainInfo={
            "AWSDomainInformation": {"OwnerId": account_id, "DomainName": local_name, "Region": ctx.region}
        },
        RemoteDomainInfo={
            "AWSDomainInformation": {"OwnerId": account_id, "DomainName": remote_name, "Region": ctx.region}
        },
    )
    conn1_id = conn1["ConnectionId"]
    ctx.on_cleanup(lambda: _safe_delete_outbound(ctx, conn1_id))

    try:
        inbound1 = _poll_until(
            ctx,
            lambda: _find_inbound(aos, conn1_id),
            lambda c: c is not None,
            timeout_s=180.0,
        )
    except AssertionError as exc:
        raise AssertionError(f"{exc}; outbound={_find_outbound(aos, conn1_id)!r}") from exc
    assert inbound1["ConnectionStatus"]["StatusCode"] in (
        "PENDING_ACCEPTANCE", "VALIDATING", "APPROVED",
    ), inbound1

    accept_resp = aos.accept_inbound_connection(ConnectionId=conn1_id)
    assert accept_resp["Connection"]["ConnectionStatus"]["StatusCode"] in (
        "APPROVED", "PROVISIONING", "ACTIVE",
    )

    active_outbound = _poll_until(
        ctx,
        lambda: _find_outbound(aos, conn1_id),
        lambda c: c is not None and c["ConnectionStatus"]["StatusCode"] == "ACTIVE",
        timeout_s=900.0,
    )
    assert active_outbound["ConnectionStatus"]["StatusCode"] == "ACTIVE"
    active_inbound = _find_inbound(aos, conn1_id)
    assert active_inbound is not None and active_inbound["ConnectionStatus"]["StatusCode"] == "ACTIVE"

    # --- Connection #2: rejected ---
    # Reversed local/remote from connection #1: ResourceAlreadyExistsException has been observed
    # keyed on the (local, remote) domain-pair tuple, not just the alias, so reusing the same pair
    # while connection #1 is still live would collide instead of creating a second, independent
    # connection.
    alias_reject = ctx.unique_name("sim2realCxR")
    conn2 = aos.create_outbound_connection(
        ConnectionAlias=alias_reject,
        LocalDomainInfo={
            "AWSDomainInformation": {"OwnerId": account_id, "DomainName": remote_name, "Region": ctx.region}
        },
        RemoteDomainInfo={
            "AWSDomainInformation": {"OwnerId": account_id, "DomainName": local_name, "Region": ctx.region}
        },
    )
    conn2_id = conn2["ConnectionId"]
    ctx.on_cleanup(lambda: _safe_delete_inbound(ctx, conn2_id))
    ctx.on_cleanup(lambda: _safe_delete_outbound(ctx, conn2_id))

    _poll_until(
        ctx,
        lambda: _find_inbound(aos, conn2_id),
        lambda c: c is not None,
        timeout_s=180.0,
    )
    reject_resp = aos.reject_inbound_connection(ConnectionId=conn2_id)
    assert reject_resp["Connection"]["ConnectionStatus"]["StatusCode"] in ("REJECTING", "REJECTED")

    rejected_final = _poll_until(
        ctx,
        lambda: _find_inbound(aos, conn2_id),
        lambda c: c is not None and c["ConnectionStatus"]["StatusCode"] == "REJECTED",
        timeout_s=180.0,
    )
    assert rejected_final["ConnectionStatus"]["StatusCode"] == "REJECTED"

    outbound2 = _find_outbound(aos, conn2_id)
    assert outbound2 is not None
    assert outbound2["ConnectionStatus"]["StatusCode"] in ("REJECTED", "REJECTING")

    # --- Delete the accepted outbound connection: it must go terminal/disappear ---
    del_resp = aos.delete_outbound_connection(ConnectionId=conn1_id)
    assert del_resp["Connection"]["ConnectionStatus"]["StatusCode"] in ("DELETING", "DELETED")

    deleted_final = _poll_until(
        ctx,
        lambda: _find_outbound(aos, conn1_id),
        lambda c: c is None or c["ConnectionStatus"]["StatusCode"] == "DELETED",
        timeout_s=300.0,
    )
    assert deleted_final is None or deleted_final["ConnectionStatus"]["StatusCode"] == "DELETED"

    # --- Delete the terminal (rejected) connection ---
    # AWS refuses DeleteInboundConnection on a REJECTED connection with
    # ValidationException ("existing status is REJECTED, unable to make necessary change") --
    # unlike the accepted connection above, a rejected one cannot be torn down from the inbound
    # side at all. Only DeleteOutboundConnection removes it.
    try:
        aos.delete_inbound_connection(ConnectionId=conn2_id)
        rejected_inbound_delete_code = rejected_inbound_delete_message = None
    except ClientError as e:
        rejected_inbound_delete_code = e.response["Error"]["Code"]
        rejected_inbound_delete_message = e.response["Error"]["Message"]
    assert rejected_inbound_delete_code == "ValidationException", (
        "expected DeleteInboundConnection on a REJECTED connection to be refused with "
        f"ValidationException, got {rejected_inbound_delete_code!r}"
    )
    expected = f"Connection {conn2_id} existing status is REJECTED, unable to make necessary change"
    assert rejected_inbound_delete_message == expected, (
        f"DeleteInboundConnection message {rejected_inbound_delete_message!r}, expected {expected!r}"
    )

    del_resp2 = aos.delete_outbound_connection(ConnectionId=conn2_id)
    assert del_resp2["Connection"]["ConnectionStatus"]["StatusCode"] in ("DELETING", "DELETED")

    deleted_outbound2 = _poll_until(
        ctx,
        lambda: _find_outbound(aos, conn2_id),
        lambda c: c is None or c["ConnectionStatus"]["StatusCode"] == "DELETED",
        timeout_s=300.0,
    )
    assert deleted_outbound2 is None or deleted_outbound2["ConnectionStatus"]["StatusCode"] == "DELETED"

    # DeleteOutboundConnection removes the outbound side only: the inbound record of a rejected
    # connection stays REJECTED rather than disappearing or turning DELETED.
    still_rejected = _find_inbound(aos, conn2_id)
    assert (
        still_rejected is not None
        and still_rejected["ConnectionStatus"]["StatusCode"] == "REJECTED"
    ), f"expected the inbound record of a rejected, outbound-deleted connection to remain REJECTED, got {still_rejected!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(ctx, probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _find_inbound(aos, connection_id):
    resp = aos.describe_inbound_connections(
        Filters=[{"Name": "connection-id", "Values": [connection_id]}]
    )
    conns = resp.get("Connections", [])
    return conns[0] if conns else None


def _find_outbound(aos, connection_id):
    resp = aos.describe_outbound_connections(
        Filters=[{"Name": "connection-id", "Values": [connection_id]}]
    )
    conns = resp.get("Connections", [])
    return conns[0] if conns else None


def _safe_delete_inbound(ctx, connection_id):
    aos = ctx.client("opensearch")
    try:
        aos.delete_inbound_connection(ConnectionId=connection_id)
    except ClientError as e:
        err = e.response["Error"]
        if err["Code"] == "ResourceNotFoundException":
            return
        # A REJECTED inbound record is terminal and never deletable; it goes with its domains.
        rejected = f"Connection {connection_id} existing status is REJECTED, unable to make necessary change"
        if err["Code"] != "ValidationException" or err.get("Message") != rejected:
            raise


def _safe_delete_outbound(ctx, connection_id):
    aos = ctx.client("opensearch")
    try:
        aos.delete_outbound_connection(ConnectionId=connection_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_minimal_domain(ctx, engine_version=None):
    aos = ctx.client("opensearch")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-osb2-")
    account_id = sts.get_caller_identity()["Account"]
    policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "es:*",
            "Resource": f"arn:aws:es:{ctx.region}:{account_id}:domain/{name}/*",
        }],
    })
    kwargs = dict(
        DomainName=name,
        # Pinning to a known-fast-provisioning engine version instead of letting CreateDomain
        # default to whatever the latest release happens to be: the default has been observed
        # taking noticeably longer to provision, and this check has to provision TWO domains
        # sequentially, so shaving minutes off each matters for staying inside the harness's
        # wall-clock budget.
        EngineVersion=engine_version or "OpenSearch_2.13",
        ClusterConfig={
            "InstanceType": INSTANCE_TYPE,
            "InstanceCount": 1,
            "DedicatedMasterEnabled": False,
            "ZoneAwarenessEnabled": False,
        },
        EBSOptions={"EBSEnabled": True, "VolumeType": "gp3", "VolumeSize": 10},
        AccessPolicies=policy,
        **_ccs_prereq_kwargs(),
    )
    # CreateDomain is throttled fairly aggressively when two are requested back-to-back (as
    # this check does for its local/remote pair) -- botocore's own default retrying (5
    # attempts, short backoff) isn't enough headroom and surfaces as a bare ThrottlingException
    # ("reached max retries: 5"). Back off ourselves with a longer, still-bounded budget.
    _call_with_backoff(aos.create_domain, **kwargs)
    ctx.on_cleanup(lambda: _safe_delete_domain(ctx, name))
    return name



def _safe_delete_domain(ctx, name):
    aos = ctx.client("opensearch")
    try:
        aos.delete_domain(DomainName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _call_with_backoff(fn, *args, timeout_s=300.0, initial_interval_s=5.0, **kwargs):
    """Retry a call with a bounded, growing backoff when it fails with ThrottlingException
    (or a LimitExceededException surfaced during throttling) -- botocore's own default
    retrying isn't enough headroom for two CreateDomain calls issued back-to-back."""
    deadline = time.monotonic() + timeout_s
    interval = initial_interval_s
    while True:
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(interval)
                interval = min(interval * 2, 30.0)
                continue
            raise


def _wait_domains_active(ctx, names, timeout_s=2400.0, interval_s=2.0):
    aos = ctx.client("opensearch")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    remaining = set(names)
    last: dict = {}
    while remaining and time.monotonic() < deadline:
        try:
            statuses = aos.describe_domains(DomainNames=sorted(remaining))["DomainStatusList"]
        except ClientError as e:
            # DescribeDomains is throttled at a low per-account rate; a throttled read is a missed poll.
            if e.response["Error"]["Code"] != "ThrottlingException":
                raise
            statuses = []
        for s in statuses:
            last[s["DomainName"]] = s
            if s.get("Created") and not s.get("Processing") and s.get("Endpoint"):
                remaining.discard(s["DomainName"])
        if remaining:
            time.sleep(interval_s)
    if remaining and _budget_spent(ctx):
        raise TimeoutError(f"domains {remaining} becoming active: the run budget ended first; not graded")
    if remaining:
        raise AssertionError(f"domains not active within {timeout_s}s: {remaining}; last={last}")
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

