"""create-user-logical-home-directory-mapping-rules."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-user-logical-home-directory-mapping-rules"
GROUP = 'overly-permissive'
SERVICES = ['transfer']

# The ${transfer:Home*} session variables (HomeBucket / HomeDirectory / HomeFolder) resolve only for
# a PATH home directory: AWS refuses a scope-down policy using any of them on a LOGICAL user, with
#   "${transfer:Home*} variable used in policy for a user with a logical home directory"
# That refusal is confinement-relevant: ${transfer:HomeBucket} on a logical user would otherwise
# expand to nothing and the Resource would degenerate.
_HOME_VAR_POLICY = json.dumps({
    'Version': '2012-10-17',
    'Statement': [
        {
            'Sid': 'AllowListingOfUserFolder',
            'Effect': 'Allow',
            'Action': ['s3:ListBucket'],
            'Resource': ['arn:aws:s3:::${transfer:HomeBucket}'],
            'Condition': {'StringLike': {'s3:prefix': [
                'home/${transfer:UserName}/*', 'home/${transfer:UserName}']}},
        },
        {
            'Sid': 'HomeDirObjectAccess',
            'Effect': 'Allow',
            'Action': ['s3:PutObject', 's3:GetObject', 's3:DeleteObject'],
            'Resource': 'arn:aws:s3:::${transfer:HomeDirectory}*',
        },
    ],
}, separators=(',', ':'))


def _scope_down_policy(bucket):
    """The LOGICAL-legal scope-down policy: ${transfer:UserName} only, with the bucket spelled out
    because AWS refuses the Home* variables for a logical home directory (see _HOME_VAR_POLICY)."""
    return json.dumps({
        'Version': '2012-10-17',
        'Statement': [
            {
                'Sid': 'AllowListingOfUserFolder',
                'Effect': 'Allow',
                'Action': ['s3:ListBucket'],
                'Resource': [f'arn:aws:s3:::{bucket}'],
                'Condition': {'StringLike': {'s3:prefix': [
                    'home/${transfer:UserName}/*', 'home/${transfer:UserName}']}},
            },
            {
                'Sid': 'HomeDirObjectAccess',
                'Effect': 'Allow',
                'Action': ['s3:PutObject', 's3:GetObject', 's3:DeleteObject'],
                'Resource': f'arn:aws:s3:::{bucket}/home/${{transfer:UserName}}/*',
            },
        ],
    }, separators=(',', ':'))


_GONE_TIMEOUT_S = 300.0
_INTERVAL_S = 15.0


def _err(fn):
    """Return (code, message) for a ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message') or ''
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_user_if_present(tf, server_id, user_name):
    """Teardown for a user the body may already have deleted."""
    try:
        tf.delete_user(ServerId=server_id, UserName=user_name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'ResourceNotFoundException':
            raise


def _create_transfer_role(ctx):
    """An IAM role trusted by transfer.amazonaws.com, owned and torn down by this check."""
    iam = ctx.client('iam')
    name = ctx.unique_name('sim2real-behav-tf-logical-role-')
    trust = {'Version': '2012-10-17', 'Statement': [{
        'Effect': 'Allow', 'Principal': {'Service': 'transfer.amazonaws.com'},
        'Action': 'sts:AssumeRole'}]}
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A LOGICAL home directory requires non-empty, non-overlapping mappings, a HomeDirectory naming
    a mapping Entry, and a scope-down Policy without ${transfer:Home*}, each refused with its own
    message; the accepted user round-trips its mappings in order and its Policy verbatim."""
    tf = ctx.client('transfer')

    server_id = tf.create_server(
        Protocols=['SFTP'], EndpointType='PUBLIC',
        IdentityProviderType='SERVICE_MANAGED',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['ServerId']

    def _reap_server(_s=server_id):
        try:
            tf.delete_server(ServerId=_s)
        except ClientError as exc:
            if exc.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                return
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

    ctx.on_cleanup(_reap_server)

    role = _create_transfer_role(ctx)

    # Bucket names only: no S3 bucket is created, because a logical mapping Target is resolved at
    # session time, not at CreateUser time.
    bucket = ctx.unique_name('sim2real-behav-tf-')
    # Entries must not overlap (real AWS refuses '/' next to '/shared'), and the first entry
    # deliberately omits Type while the second sets it explicitly.
    mappings = [
        {'Entry': '/home', 'Target': f'/{bucket}/home/${{transfer:UserName}}'},
        {'Entry': '/shared', 'Target': f'/{bucket}/shared', 'Type': 'DIRECTORY'},
    ]
    policy = _scope_down_policy(bucket)
    user = ctx.unique_name('sim2realbehavlogical')
    user_hd = ctx.unique_name('sim2realbehavlogicalhd')

    def _usernames():
        return {u['UserName'] for u in tf.list_users(ServerId=server_id)['Users']}

    assert _usernames() == set(), f"a fresh server must have no users, got {_usernames()}"

    # --- negative 1: LOGICAL without mappings ---------------------------------------------
    # Omitted rather than []: botocore enforces the model's min length of 1 client-side.
    code_nomap, msg_nomap = _err(lambda: tf.create_user(
        ServerId=server_id, UserName=user, Role=role, HomeDirectoryType='LOGICAL'))
    assert code_nomap == 'InvalidRequestException', (
        f"HomeDirectoryType=LOGICAL with no HomeDirectoryMappings must be rejected with "
        f"InvalidRequestException, got {code_nomap!r}: {msg_nomap!r}")
    assert msg_nomap == 'HomeDirectoryMappings must not be empty', (
        f"unexpected missing-mappings diagnostic: {msg_nomap!r}")
    assert _usernames() == set(), (
        f"the rejected LOGICAL user was created anyway: {_usernames()}")

    # --- negative 2: a HomeDirectory that is not one of the mapping ENTRIES -----------------
    # AWS does NOT treat HomeDirectory and HomeDirectoryMappings as mutually exclusive; it
    # requires HomeDirectory to name one of the Entries, and the diagnostic quotes the missing
    # path. It is compared against the ENTRY, not the Target: '/{bucket}/shared' (a Target) is
    # refused, '/home' (an Entry) is accepted.
    unmapped_home = f'/{bucket}/home'
    code_both, msg_both = _err(lambda: tf.create_user(
        ServerId=server_id, UserName=user, Role=role, HomeDirectoryType='LOGICAL',
        HomeDirectory=unmapped_home, HomeDirectoryMappings=mappings))
    assert code_both == 'InvalidRequestException', (
        f"a HomeDirectory absent from HomeDirectoryMappings must be rejected with "
        f"InvalidRequestException, got {code_both!r}: {msg_both!r}")
    assert msg_both == (
        f"[HomeDirectoryMappings does not contain home directory '{unmapped_home}' mapping]"
    ), f"the refusal must quote the unmapped home directory, got {msg_both!r}"
    assert _usernames() == set(), (
        f"the rejected unmapped-home user was created anyway: {_usernames()}")

    # --- negative 3: a scope-down Policy using a ${transfer:Home*} session variable ----------
    code_var, msg_var = _err(lambda: tf.create_user(
        ServerId=server_id, UserName=user, Role=role, HomeDirectoryType='LOGICAL',
        HomeDirectoryMappings=mappings, Policy=_HOME_VAR_POLICY))
    assert code_var == 'InvalidRequestException', (
        f"a ${{transfer:Home*}} variable in the Policy of a LOGICAL user must be rejected with "
        f"InvalidRequestException, got {code_var!r}: {msg_var!r}")
    assert msg_var == (
        '${transfer:Home*} variable used in policy for a user with a logical home directory'
    ), f"unexpected Home*-variable diagnostic: {msg_var!r}"
    assert _usernames() == set(), (
        f"the rejected Home*-variable user was created anyway: {_usernames()}")

    # Three distinct defects must be three distinct diagnostics: all three share
    # InvalidRequestException, so only the message tells them apart.
    msgs = [msg_nomap, msg_both, msg_var]
    assert all(msgs), f"an InvalidRequestException carried no Message: {msgs}"
    assert len(set(msgs)) == 3, (
        f"three different LOGICAL-configuration defects produced indistinguishable diagnostics: "
        f"{msgs}")

    # --- the corrected rule, proved positively: HomeDirectory naming an Entry IS accepted ----
    tf.create_user(
        ServerId=server_id, UserName=user_hd, Role=role, HomeDirectoryType='LOGICAL',
        HomeDirectory='/home', HomeDirectoryMappings=mappings,
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: _delete_user_if_present(tf, server_id, user_hd))
    described_hd = tf.describe_user(ServerId=server_id, UserName=user_hd)['User']
    assert described_hd.get('HomeDirectory') == '/home', (
        f"a LOGICAL user whose HomeDirectory names a mapping Entry must echo it verbatim, got "
        f"{described_hd.get('HomeDirectory')!r}")
    assert described_hd['HomeDirectoryType'] == 'LOGICAL', described_hd.get('HomeDirectoryType')
    tf.delete_user(ServerId=server_id, UserName=user_hd)

    # --- control: the same request with the one broken thing fixed ------------------------
    created = tf.create_user(
        ServerId=server_id, UserName=user, Role=role, HomeDirectoryType='LOGICAL',
        HomeDirectoryMappings=mappings, Policy=policy,
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda: _delete_user_if_present(tf, server_id, user))
    assert created['UserName'] == user, created
    assert created['ServerId'] == server_id, created

    described = tf.describe_user(ServerId=server_id, UserName=user)['User']
    assert described['UserName'] == user, described
    assert described['HomeDirectoryType'] == 'LOGICAL', described.get('HomeDirectoryType')
    assert 'HomeDirectory' not in described, (
        f"a LOGICAL user must not describe a HomeDirectory, got "
        f"{described.get('HomeDirectory')!r}")
    assert f':user/{server_id}/{user}' in described['Arn'], described['Arn']
    assert described['Role'] == role, described.get('Role')

    got = described['HomeDirectoryMappings']
    # An ordered sequence: mapping precedence is positional, so a store that returns a set or
    # reorders entries changes which prefix a session resolves.
    assert [m['Entry'] for m in got] == ['/home', '/shared'], (
        f"HomeDirectoryMappings must round-trip in submission order, got "
        f"{[m.get('Entry') for m in got]}")
    # AWS RESOLVES ${transfer:UserName} inside a mapping Target at CreateUser time, while leaving
    # the SAME variable UNRESOLVED in the scope-down Policy (asserted below): a mapping is per-user
    # configuration resolved once, a policy a per-session template resolved on every login.
    resolved_targets = [m['Target'].replace('${transfer:UserName}', user) for m in mappings]
    assert [m['Target'] for m in got] == resolved_targets, (
        f"mapping Targets must come back with ${{transfer:UserName}} resolved to the user's own "
        f"name; expected {resolved_targets}, got {[m.get('Target') for m in got]}")
    # HomeDirectoryMapEntry.Type carries no @default in the model, and real AWS does NOT
    # materialise one: the entry submitted without a Type comes back with the member ABSENT, while
    # the explicitly-set one is preserved. Both directions matter -- an emulator that helpfully
    # fills in 'DIRECTORY' invents a field, and one that drops the explicit 'DIRECTORY' loses the
    # customer's configuration.
    assert 'Type' not in got[0], (
        f"an entry submitted without a Type must come back without one, got {got[0]!r}")
    assert got[1].get('Type') == 'DIRECTORY', (
        f"an explicitly-set HomeDirectoryMapEntry.Type must be preserved, got {got[1]!r}")
    assert '${transfer:UserName}' not in got[0]['Target'], (
        f"the session variable in a mapping Target is resolved at CreateUser time, not stored "
        f"as a template, got {got[0]['Target']!r}")
    assert got[0]['Target'].endswith(f'/home/{user}'), (
        f"the resolved mapping Target must end in the user's own directory /home/{user}, got "
        f"{got[0]['Target']!r}")
    # The second entry carried no variable, so it is byte-identical: resolution is a substitution,
    # not a rewrite of every Target.
    assert got[1]['Target'] == mappings[1]['Target'], (
        f"a Target with no session variable must round-trip verbatim, got {got[1]['Target']!r}")

    # The scope-down policy must round-trip byte-for-byte: this string IS the confinement.
    assert described.get('Policy'), (
        f"the scope-down Policy was dropped from DescribeUser: {described!r}")
    assert json.loads(described['Policy']) == json.loads(policy), (
        f"the scope-down Policy did not round-trip; a rewritten or widened policy is a "
        f"confinement defect. got {described['Policy']!r}")
    assert '${transfer:UserName}' in described['Policy'], (
        f"the Policy's session variables must be stored unresolved: {described['Policy']!r}")

    # ListedUser is a projection and must agree with the described user.
    listed = [u for u in tf.list_users(ServerId=server_id)['Users'] if u['UserName'] == user]
    assert len(listed) == 1, listed
    assert listed[0]['HomeDirectoryType'] == 'LOGICAL', listed[0]
    assert listed[0].get('SshPublicKeyCount') == 0, listed[0]
    assert 'HomeDirectoryMappings' not in listed[0], (
        f"ListedUser must not carry HomeDirectoryMappings; it is a projection: "
        f"{sorted(listed[0])}")

    tf.delete_user(ServerId=server_id, UserName=user)
    code_gone, msg_gone = _err(lambda: tf.describe_user(ServerId=server_id, UserName=user))
    assert code_gone == 'ResourceNotFoundException', (
        f"DescribeUser after DeleteUser must raise ResourceNotFoundException, got {code_gone!r}")
    assert msg_gone == 'Unknown user', f"unexpected not-found message: {msg_gone!r}"
    assert _usernames() == set(), f"deleted user still listed: {_usernames()}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
