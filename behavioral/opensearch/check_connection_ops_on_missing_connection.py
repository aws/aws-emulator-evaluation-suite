"""connection-ops-on-missing-connection."""
from __future__ import annotations

import secrets
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "connection-ops-on-missing-connection"
GROUP = 'connections'
SERVICES = ['opensearch']

_THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded")

# Detail prefix for a state the target accepted but never reached, so it scores as a fail
# rather than an environment error.
STATE_MARKER = "TARGET_STATE_UNIMPLEMENTED"


def _never_ready(msg: str):
    """Build the failure for a resource that never reached its ready state within the budget."""
    return AssertionError(f"{STATE_MARKER}: {msg}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Accept/Reject/Delete on a never-existing connection id raise ResourceNotFoundException,
    while the same ops on a real, validated connection (positive control) never read as missing."""
    osc = ctx.client('opensearch')
    account_id = ctx.client('sts').get_caller_identity()['Account']
    region = ctx.region

    local = _create_domain(ctx, osc)
    remote = _create_domain(ctx, osc)
    _wait_domain_active(ctx, osc, local)
    _wait_domain_active(ctx, osc, remote)

    accept_id = _open_connection(ctx, osc, account_id, region, local, remote)
    reject_id = _open_connection(ctx, osc, account_id, region, remote, local)

    # A connection that fails cross-cluster validation never materialises an inbound side,
    # so it cannot serve as the positive control.
    for cid in (accept_id, reject_id):
        validated = _poll_until(
            lambda _c=cid: _outbound(osc, _c),
            lambda c: c is not None
            and c.get('ConnectionStatus', {}).get('StatusCode')
            in ('PENDING_ACCEPTANCE', 'APPROVED', 'ACTIVE', 'VALIDATION_FAILED'),
            timeout_s=600,
            description=f'outbound connection {cid} validated',
        )
        assert validated['ConnectionStatus']['StatusCode'] != 'VALIDATION_FAILED', (
            f"cross-cluster validation FAILED for outbound {cid}, so no inbound "
            f"connection can exist to run the positive control against: "
            f"{validated['ConnectionStatus']}"
        )

    for cid in (accept_id, reject_id):
        _poll_until(
            lambda _c=cid: _inbound(osc, _c),
            lambda c: c is not None,
            timeout_s=600,
            description=f'inbound connection {cid} materialised',
        )

    # --- positive control: real, validated ids must never read as missing ---
    _assert_not_missing('AcceptInboundConnection', lambda: osc.accept_inbound_connection(ConnectionId=accept_id))
    _assert_not_missing('RejectInboundConnection', lambda: osc.reject_inbound_connection(ConnectionId=reject_id))
    _assert_not_missing('DeleteOutboundConnection', lambda: osc.delete_outbound_connection(ConnectionId=reject_id))
    _assert_not_missing('DeleteInboundConnection', lambda: osc.delete_inbound_connection(ConnectionId=accept_id))

    # --- negative: an id that never existed must 404 on all four ops ---
    bogus_id = ctx.unique_name('sim2real-behav-conn-missing-')
    for label, fn in (
        ('AcceptInboundConnection', lambda: osc.accept_inbound_connection(ConnectionId=bogus_id)),
        ('RejectInboundConnection', lambda: osc.reject_inbound_connection(ConnectionId=bogus_id)),
        ('DeleteInboundConnection', lambda: osc.delete_inbound_connection(ConnectionId=bogus_id)),
        ('DeleteOutboundConnection', lambda: osc.delete_outbound_connection(ConnectionId=bogus_id)),
    ):
        refusal = _refusal(fn)
        assert refusal == ('ResourceNotFoundException', f'Connection ID {bogus_id} does not exist'), (
            f'{label} on a missing connection id: expected ResourceNotFoundException with AWS exact '
            f'message, got {refusal!r}'
        )


def _refusal(fn) -> "tuple[str, str]":
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: a target that accepts what AWS refuses is the divergence this check exists to catch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message', '')
    raise AssertionError(f'expected a ClientError, but the call succeeded and returned {result!r}')


def _assert_not_missing(label, fn) -> None:
    """A real, validated connection id may be accepted or refused for a state reason, but it
    must never read as missing."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response['Error']['Code']
        assert code != 'ResourceNotFoundException', (
            f'{label} misreported a real connection id as missing: {code}'
        )


def _ccs_prereq_kwargs() -> dict:
    """CreateDomain kwargs that make a domain eligible as a cross-cluster peer; without them the
    outbound connection goes VALIDATION_FAILED and no inbound connection ever materialises."""
    return {
        'NodeToNodeEncryptionOptions': {'Enabled': True},
        'EncryptionAtRestOptions': {'Enabled': True},
        'DomainEndpointOptions': {'EnforceHTTPS': True},
        'AdvancedSecurityOptions': {
            'Enabled': True,
            'InternalUserDatabaseEnabled': True,
            'MasterUserOptions': {
                'MasterUserName': 'sim2real-master',
                'MasterUserPassword': f'Sim2Real!{secrets.token_urlsafe(18)}Aa1',
            },
        },
    }


def _create_domain(ctx, osc) -> str:
    name = ctx.unique_name('sim2real-behav-os-conn-')[:28].rstrip('-')
    kwargs = dict(
        DomainName=name,
        EngineVersion='OpenSearch_2.11',
        ClusterConfig={
            'InstanceType': 'm5.large.search',
            'InstanceCount': 1,
            'DedicatedMasterEnabled': False,
            'ZoneAwarenessEnabled': False,
        },
        EBSOptions={'EBSEnabled': True, 'VolumeType': 'gp2', 'VolumeSize': 10},
        TagList=[{'Key': 'sim2real', 'Value': 'connection-ops-on-missing-connection'}],
        **_ccs_prereq_kwargs(),
    )
    for attempt in range(12):
        try:
            osc.create_domain(**kwargs)
            break
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') not in _THROTTLE_CODES:
                raise
            time.sleep(6.0 * (attempt + 1))
    else:
        raise AssertionError('still throttled after 12 CreateDomain attempts')
    ctx.on_cleanup(lambda: _delete_domain_when_unblocked(osc, name))
    return name


def _wait_domain_active(ctx, osc, domain_name, timeout_s: float = 1450) -> dict:
    """A real OpenSearch domain needs 10-20 min to go Active; every target polls the same
    terminal condition under the same budget."""
    budget = timeout_s
    deadline = time.monotonic() + budget
    last = None
    while time.monotonic() < deadline:
        last = osc.describe_domain(DomainName=domain_name)['DomainStatus']
        if last.get('Processing') is False and last.get('Created') is True:
            return last
        time.sleep(2)
    raise _never_ready(f'domain {domain_name} never became Active within {budget}s')


def _open_connection(ctx, osc, account_id, region, local, remote) -> str:
    def _attempt():
        alias = ('sim2realCx' + uuid.uuid4().hex)[:20]
        return osc.create_outbound_connection(
            LocalDomainInfo={
                'AWSDomainInformation': {'OwnerId': account_id, 'DomainName': local, 'Region': region}
            },
            RemoteDomainInfo={
                'AWSDomainInformation': {'OwnerId': account_id, 'DomainName': remote, 'Region': region}
            },
            ConnectionAlias=alias,
            ConnectionMode='DIRECT',
        )

    last_exc = None
    created = None
    for attempt in range(4):
        try:
            created = _attempt()
            break
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceAlreadyExistsException' and attempt < 3:
                last_exc = exc
                time.sleep(2.0)
                continue
            raise
    if created is None:
        raise AssertionError(f'could not open connection after retries: {last_exc}')
    cid = created['ConnectionId']
    ctx.on_cleanup(lambda _c=cid: _teardown_connection(osc, _c))
    return cid


_CONNECTION_GONE = ('DELETED', 'REJECTED', 'VALIDATION_FAILED')
_CONNECTION_BUSY = ('PROVISIONING', 'VALIDATING', 'APPROVED', 'REJECTING', 'DELETING')


def _teardown_connection(osc, cid, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    """Delete both sides of a connection and wait until neither side holds the domains. A side
    in a transitional state refuses deletion, so it is retried once it settles; DeleteDomain is
    refused while any connection is still live."""
    deadline = time.monotonic() + timeout_s
    states = None
    while time.monotonic() < deadline:
        sides = (('outbound', _outbound(osc, cid)), ('inbound', _inbound(osc, cid)))
        states = {side: c['ConnectionStatus']['StatusCode'] for side, c in sides if c is not None}
        if all(st in _CONNECTION_GONE for st in states.values()):
            return
        for side, st in states.items():
            if st in _CONNECTION_GONE or st in _CONNECTION_BUSY:
                continue
            delete = osc.delete_outbound_connection if side == 'outbound' else osc.delete_inbound_connection
            try:
                delete(ConnectionId=cid)
            except ClientError as exc:
                if exc.response.get('Error', {}).get('Code') not in ('ResourceNotFoundException', 'ValidationException'):
                    raise
        time.sleep(interval_s)
    raise AssertionError(f'connection {cid} still live after {timeout_s}s of teardown: {states}')


def _delete_domain_when_unblocked(osc, name, timeout_s: float = 900.0, interval_s: float = 20.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            osc.delete_domain(DomainName=name)
            return
        except ClientError as exc:
            code = exc.response.get('Error', {}).get('Code')
            if code == 'ResourceNotFoundException':
                return
            if code != 'ValidationException' or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _outbound(osc, cid):
    conns = osc.describe_outbound_connections(
        Filters=[{'Name': 'connection-id', 'Values': [cid]}]
    ).get('Connections', [])
    return conns[0] if conns else None


def _inbound(osc, cid):
    conns = osc.describe_inbound_connections(
        Filters=[{'Name': 'connection-id', 'Values': [cid]}]
    ).get('Connections', [])
    return conns[0] if conns else None


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=6.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise _never_ready(f'{description} not met within {timeout_s}s. Last result: {last!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
