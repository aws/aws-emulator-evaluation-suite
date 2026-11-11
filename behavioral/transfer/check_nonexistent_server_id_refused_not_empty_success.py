"""nonexistent-server-id-refused-not-empty-success."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "nonexistent-server-id-refused-not-empty-success"
GROUP = 'error-semantics'
SERVICES = ['transfer']

# A syntactically VALID but nonexistent ServerId. smithy ServerId is length exactly 19 with
# pattern ^s-([0-9a-f]{17})$, and botocore.validate enforces the `min` length client-side, so a
# short sentinel like 's-nosuch' never reaches the service at all.
_ABSENT_SERVER = 's-' + '0' * 17

# Likewise: SshPublicKeyId is length exactly 21, pattern ^key-[0-9a-f]{17}$.
_ABSENT_KEY = 'key-' + '0' * 17

# CreateUser's Role is PASSED to the service, so real AWS validates the ARN's ACCOUNT before it
# ever resolves the ServerId: a role ARN in a foreign account is refused with
# AccessDeniedException "Cross-account pass role is not allowed.", which masks the
# reference-integrity contract under test. The role NAME need not
# exist -- a nonexistent role in the CALLER's own account still yields ResourceNotFoundException
# on the absent server -- so the ARN is built from the caller's own account id and the
# cross-account form is asserted separately below as the ordering fact it is.
_ROLE_NAME = 'sim2real-behav-nonexistent-role'
_FOREIGN_ACCOUNT_ROLE = f'arn:aws:iam::111122223333:role/{_ROLE_NAME}'


def _err(fn):
    """(code, response) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Every server-scoped operation refuses an absent ServerId with ResourceNotFoundException
    carrying the required Resource/ResourceType members, never an empty success (ListUsers
    returning no users would hide that the server does not exist).
    """
    tf = ctx.client('transfer')
    account = ctx.client('sts').get_caller_identity()['Account']
    same_account_role = f'arn:aws:iam::{account}:role/{_ROLE_NAME}'

    # ListUsers must RAISE, not return an empty page. Asserted first and separately because
    # an empty list would be indistinguishable from a server with no users.
    resp_users = None
    msg_users = None
    try:
        resp_users = tf.list_users(ServerId=_ABSENT_SERVER)
        code_users = None
    except ClientError as exc:
        code_users = exc.response.get('Error', {}).get('Code')
        msg_users = exc.response.get('Error', {}).get('Message')
    assert code_users == 'ResourceNotFoundException', (
        f"ListUsers on the absent server {_ABSENT_SERVER} must raise "
        f"ResourceNotFoundException, not succeed with {resp_users!r}"
    )
    assert msg_users == 'Unknown server', f"ListUsers: unexpected message {msg_users!r}"

    cases = {
        'DescribeServer': lambda: tf.describe_server(ServerId=_ABSENT_SERVER),
        'StartServer': lambda: tf.start_server(ServerId=_ABSENT_SERVER),
        'StopServer': lambda: tf.stop_server(ServerId=_ABSENT_SERVER),
        'DeleteServer': lambda: tf.delete_server(ServerId=_ABSENT_SERVER),
        'UpdateServer': lambda: tf.update_server(
            ServerId=_ABSENT_SERVER, PreAuthenticationLoginBanner='sim2real-behav'),
        'CreateUser': lambda: tf.create_user(
            ServerId=_ABSENT_SERVER, UserName='sim2realbehavuser', Role=same_account_role,
            HomeDirectory='/sim2real-behav', HomeDirectoryType='PATH'),
        'ListUsers': lambda: tf.list_users(ServerId=_ABSENT_SERVER),
        'DeleteSshPublicKey': lambda: tf.delete_ssh_public_key(
            ServerId=_ABSENT_SERVER, UserName='sim2realbehavuser',
            SshPublicKeyId=_ABSENT_KEY),
    }
    for op, call in cases.items():
        code, resp = _err(call)
        assert code == 'ResourceNotFoundException', (
            f"{op} on the absent server {_ABSENT_SERVER} must raise ResourceNotFoundException, "
            f"got {code!r}"
        )
        assert resp.get('ResourceType') == 'Server', (
            f"{op}: ResourceNotFoundException.ResourceType must be 'Server' "
            f"(a required member of the modeled error), got {resp.get('ResourceType')!r}"
        )
        assert resp.get('Resource') == _ABSENT_SERVER, (
            f"{op}: ResourceNotFoundException.Resource must name the missing server "
            f"{_ABSENT_SERVER!r}, got {resp.get('Resource')!r}"
        )
        assert resp.get('Error', {}).get('Message') == 'Unknown server', (
            f"{op}: unexpected ResourceNotFoundException message "
            f"{resp.get('Error', {}).get('Message')!r}"
        )

    # Validation ORDER: the passed Role's account is checked BEFORE the ServerId is resolved, so
    # the SAME CreateUser call with a foreign-account role ARN is refused with a DIFFERENT,
    # more specific error and never reaches the not-found path.
    cross_code, cross_resp = _err(lambda: tf.create_user(
        ServerId=_ABSENT_SERVER, UserName='sim2realbehavuser', Role=_FOREIGN_ACCOUNT_ROLE,
        HomeDirectory='/sim2real-behav', HomeDirectoryType='PATH'))
    assert cross_code == 'AccessDeniedException', (
        f"CreateUser passing a role from another account must be refused with "
        f"AccessDeniedException before the ServerId is resolved, got {cross_code!r}"
    )
    assert cross_resp['Error'].get('Message') == 'Cross-account pass role is not allowed.', (
        f"the cross-account pass-role refusal must say so, got "
        f"{cross_resp['Error'].get('Message')!r}"
    )

    # Control: the account-scoped list that takes no ServerId still succeeds and does not
    # contain the sentinel, so the refusals above are reference-integrity, not an outage.
    servers = tf.list_servers()
    assert isinstance(servers.get('Servers'), list), servers
    assert _ABSENT_SERVER not in {s['ServerId'] for s in servers['Servers']}, (
        f"the absent sentinel {_ABSENT_SERVER} is present in ListServers"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
