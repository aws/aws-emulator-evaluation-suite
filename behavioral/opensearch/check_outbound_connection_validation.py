"""outbound-connection-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "outbound-connection-validation"
GROUP = 'connections'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOutboundConnection to nonexistent local/remote domains is accepted, but async
    validation must leave it VALIDATION_FAILED (never ACTIVE) in DescribeOutboundConnections."""
    os = ctx.client('opensearch')
    account_id = ctx.client('sts').get_caller_identity()['Account']
    missing_local = _missing_domain_name(ctx)
    missing_remote = _missing_domain_name(ctx)
    alias = ctx.unique_name('sim2real-behav-conn-')[:20]

    # Well-formed OwnerId/DomainName/Region leave nothing to reject synchronously.
    created = os.create_outbound_connection(
        LocalDomainInfo={'AWSDomainInformation': {'OwnerId': account_id, 'DomainName': missing_local, 'Region': ctx.region}},
        RemoteDomainInfo={'AWSDomainInformation': {'OwnerId': account_id, 'DomainName': missing_remote, 'Region': ctx.region}},
        ConnectionAlias=alias,
    )
    connection_id = created['ConnectionId']
    ctx.on_cleanup(lambda: _delete_outbound(os, connection_id))

    def _outbound():
        conns = os.describe_outbound_connections(
            Filters=[{'Name': 'connection-id', 'Values': [connection_id]}]
        ).get('Connections', [])
        return conns[0] if conns else None

    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        last = _outbound()
        code = (last or {}).get('ConnectionStatus', {}).get('StatusCode')
        if code in ('VALIDATION_FAILED', 'ACTIVE', 'PENDING_ACCEPTANCE'):
            break
        time.sleep(5.0)
    assert last is not None, f'connection {connection_id} disappeared from DescribeOutboundConnections before validating'
    status = last['ConnectionStatus']['StatusCode']
    assert status == 'VALIDATION_FAILED', (
        f'outbound connection {connection_id} to nonexistent domains {missing_local!r}/{missing_remote!r} '
        f'reached {status!r} instead of VALIDATION_FAILED -- a target that lets this validate must be '
        f'materializing the referenced domains, not genuinely checking them'
    )


def _delete_outbound(os, connection_id):
    try:
        os.delete_outbound_connection(ConnectionId=connection_id)
    except ClientError as e:
        if e.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
