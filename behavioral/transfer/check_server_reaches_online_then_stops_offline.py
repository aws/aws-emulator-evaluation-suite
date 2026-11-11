"""server-reaches-online-then-stops-offline."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-reaches-online-then-stops-offline"
GROUP = 'lifecycle'
SERVICES = ['transfer']

_SERVER_ID_RE = re.compile(r'^s-[0-9a-f]{17}$')
# smithy SecurityPolicyName pattern, com.amazonaws.transfer#SecurityPolicyName.
_POLICY_RE = re.compile(r'^Transfer[A-Za-z0-9]*SecurityPolicy-[A-Za-z0-9-]+$')

# Every member of com.amazonaws.transfer#State. Enumerated so an out-of-enum value is caught
# rather than silently treated as "not yet ONLINE".
_STATES = {'OFFLINE', 'ONLINE', 'STARTING', 'STOPPING', 'START_FAILED', 'STOP_FAILED'}

_ONLINE_TIMEOUT_S = 900.0
_OFFLINE_TIMEOUT_S = 900.0
_GONE_TIMEOUT_S = 300.0
_INTERVAL_S = 15.0


def _poll(fn, pred, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {what}; last observation: {last!r}")
        time.sleep(interval_s)


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Transfer server goes OFFLINE -> STARTING -> ONLINE and back to OFFLINE on StopServer, with
    exact state equality and a fully populated DescribedServer and ListedServer while it is up."""
    # Creates a billable SFTP endpoint and can take ~20 minutes against AWS.
    # Teardown polls until the server is actually gone rather than firing and forgetting.

    tf = ctx.client('transfer')

    server_id = tf.create_server(
        Protocols=['SFTP'],
        EndpointType='PUBLIC',
        IdentityProviderType='SERVICE_MANAGED',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )['ServerId']

    def _reap(_s=server_id):
        try:
            tf.delete_server(ServerId=_s)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return  # already deleted by the happy path below
            raise
        deadline = time.monotonic() + _GONE_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                tf.describe_server(ServerId=_s)
            except ClientError as exc:
                if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                    return
                raise
            time.sleep(_INTERVAL_S)
        raise AssertionError(f"server {_s} still present {_GONE_TIMEOUT_S}s after DeleteServer")

    # Registered immediately after creation so a failure anywhere below still stops the meter.
    ctx.on_cleanup(_reap)

    assert _SERVER_ID_RE.match(server_id), f"ServerId {server_id!r} violates ^s-[0-9a-f]{{17}}$"

    def _state():
        srv = tf.describe_server(ServerId=server_id)['Server']
        st = srv.get('State')
        assert st in _STATES, f"State {st!r} is not a member of the modeled State enum"
        assert st != 'START_FAILED', f"server entered START_FAILED: {srv!r}"
        return srv

    srv = _poll(_state, lambda s: s['State'] == 'ONLINE',
                timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
                what=f"server {server_id} to reach exactly ONLINE")

    assert srv['ServerId'] == server_id, srv
    assert f':server/{server_id}' in srv['Arn'], srv['Arn']
    assert srv['Protocols'] == ['SFTP'], (
        f"Protocols must echo exactly ['SFTP'], got {srv.get('Protocols')!r}"
    )
    assert srv['EndpointType'] == 'PUBLIC', srv.get('EndpointType')
    assert srv['IdentityProviderType'] == 'SERVICE_MANAGED', srv.get('IdentityProviderType')
    assert srv['Domain'] == 'S3', (
        f"Domain must default to S3 when no Domain is supplied, got {srv.get('Domain')!r}"
    )
    assert srv['UserCount'] == 0, (
        f"a server with no users must report UserCount 0, got {srv.get('UserCount')!r}"
    )
    fingerprint = srv.get('HostKeyFingerprint') or ''
    assert fingerprint.startswith('SHA256:'), (
        f"an ONLINE SFTP server must publish a SHA256 host key fingerprint, got "
        f"{fingerprint!r} — the service generates the host key, the caller never supplies one"
    )
    assert _POLICY_RE.match(srv.get('SecurityPolicyName') or ''), (
        f"SecurityPolicyName must be defaulted to a catalog policy name, got "
        f"{srv.get('SecurityPolicyName')!r}"
    )
    assert {'Key': 'sim2real', 'Value': CHECK} in (srv.get('Tags') or []), srv.get('Tags')

    # ListedServer is a projection of the described shape and must agree with it.
    listed = None
    for page in tf.get_paginator('list_servers').paginate():
        for s in page.get('Servers', []):
            if s['ServerId'] == server_id:
                listed = s
    assert listed is not None, f"ONLINE server {server_id} absent from ListServers"
    assert listed['State'] == 'ONLINE', listed
    assert listed['Arn'] == srv['Arn'], (listed['Arn'], srv['Arn'])
    assert listed['UserCount'] == 0, listed
    assert listed['EndpointType'] == 'PUBLIC', listed
    assert listed['IdentityProviderType'] == 'SERVICE_MANAGED', listed
    assert 'Protocols' not in listed, (
        f"ListedServer must not carry Protocols; it is a projection: {sorted(listed)}"
    )
    # NOTE: reaching ONLINE means the control plane published an endpoint. Whether that endpoint
    # actually completes an SSH key exchange on port 22 is not asserted by this check.

    tf.stop_server(ServerId=server_id)
    srv = _poll(_state, lambda s: s['State'] == 'OFFLINE',
                timeout_s=_OFFLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
                what=f"server {server_id} to reach exactly OFFLINE after StopServer")
    assert srv['UserCount'] == 0, srv
    # A stopped server keeps its identity and configuration; only State changes.
    assert srv['Protocols'] == ['SFTP'], srv.get('Protocols')
    assert f':server/{server_id}' in srv['Arn'], srv['Arn']

    tf.start_server(ServerId=server_id)
    _poll(_state, lambda s: s['State'] == 'ONLINE',
          timeout_s=_ONLINE_TIMEOUT_S, interval_s=_INTERVAL_S,
          what=f"server {server_id} to return to exactly ONLINE after StartServer")

    # Terminal deletion, asserted here rather than left to cleanup, because DeleteServer is the
    # only call that stops billing and its post-conditions are uncovered.
    tf.delete_server(ServerId=server_id)
    _poll(lambda: server_id in {
              s['ServerId']
              for page in tf.get_paginator('list_servers').paginate()
              for s in page.get('Servers', [])},
          lambda listed: not listed,
          timeout_s=_GONE_TIMEOUT_S, interval_s=_INTERVAL_S,
          what=f"server {server_id} to leave ListServers after delete")
    code_gone, msg_gone = _err(lambda: tf.describe_server(ServerId=server_id))
    assert code_gone == 'ResourceNotFoundException', (
        f"DescribeServer({server_id}) after delete must raise ResourceNotFoundException, got "
        f"{code_gone!r}"
    )
    assert msg_gone == 'Unknown server', f"DescribeServer after delete: unexpected message {msg_gone!r}"

    code_again, msg_again = _err(lambda: tf.delete_server(ServerId=server_id))
    assert code_again == 'ResourceNotFoundException', (
        f"a second DeleteServer must raise ResourceNotFoundException, not succeed idempotently; "
        f"got {code_again!r}"
    )
    assert msg_again == 'Unknown server', f"second DeleteServer: unexpected message {msg_again!r}"
    # Partition + account derived from the server ARN rather than an sts:GetCallerIdentity call,
    # so this check records only transfer operations.
    arn_parts = srv['Arn'].split(':')
    ghost_role = f"arn:{arn_parts[1]}:iam::{arn_parts[4]}:role/sim2real-behav-ghost-role"
    code_user, msg_user = _err(lambda: tf.create_user(
        ServerId=server_id, UserName='sim2realbehavghost', Role=ghost_role,
        HomeDirectory='/sim2real-behav', HomeDirectoryType='PATH'))
    assert code_user == 'ResourceNotFoundException', (
        f"CreateUser against a deleted server must raise ResourceNotFoundException, got "
        f"{code_user!r}"
    )
    assert msg_user == 'Unknown server', f"CreateUser on a deleted server: unexpected message {msg_user!r}"
    assert server_id not in {
        s['ServerId']
        for page in tf.get_paginator('list_servers').paginate()
        for s in page.get('Servers', [])
    }, f"deleted server {server_id} still listed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
