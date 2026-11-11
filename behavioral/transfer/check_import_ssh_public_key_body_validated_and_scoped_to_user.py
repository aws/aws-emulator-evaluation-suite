"""import-ssh-public-key-body-validated-and-scoped-to-user."""
from __future__ import annotations

import base64
import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-ssh-public-key-body-validated-and-scoped-to-user"
GROUP = 'overly-permissive'
SERVICES = ['transfer']

# smithy SshPublicKeyId: length exactly 21, pattern ^key-[0-9a-f]{17}$.
_KEY_ID_RE = re.compile(r'^key-[0-9a-f]{17}$')

# A real 2048-bit RSA public key that Transfer accepts. A public key is not a secret.
_KEY_PAYLOAD = (
    'AAAAB3NzaC1yc2EAAAADAQABAAABAQDsCjIO8pcN8dl7lEHZ/LZdetfyp08qzcCli+NzEpgiyFtrspSd2yApFbR8'
    'rrnO7Oq1TKPSwXF/icHA8XVp/MR+MndNykPPOQ6gEUxawqB0ASe7NupvL4F0cuuaePXwjf4rLJzOAmJOOx6GTvGT'
    'GDFzWjajkAXLYQK/QKE6eRAcbfWYlwX6jyNRI9IWu7pPVecmg3DjI9SwPDq5fpr8/S2PGVRXSgF4VUN3asiyB9ml'
    'OviQvW5mGlOFnADjLGA4rmf0rx2ZXpbDskZsKFpp8537sVRMSIrWE7pQUFUsi4zPLM7G+/2Sy/u6j8O4Es/6kVDA'
    'hP33H6TEMTSAMK4It27h'
)
_GOOD_BODY = f'ssh-rsa {_KEY_PAYLOAD}'

# Real Transfer validates the ALGORITHM NAME against a supported set and requires a non-empty,
# base64-decodable payload -- and nothing else. Everything it refuses collapses onto ONE diagnostic.
_BAD_KEY_MSG = 'Unsupported or invalid SSH public key format'

# Refused: the algorithm name is not one real Transfer supports. ssh-dss is a genuine SSH public
# key algorithm that Transfer deliberately does not accept; ssh-foo is not an algorithm at all.
# Both satisfy the smithy SshPublicKeyBody pattern ^\s*(ssh|ecdsa)-[a-z0-9-]+... so both reach the
# service, and both come back with _BAD_KEY_MSG.
_UNSUPPORTED_ALGO_BODY = f'ssh-dss {_KEY_PAYLOAD}'
_UNKNOWN_ALGO_BODY = f'ssh-foo {_KEY_PAYLOAD}'

# Refused: a supported algorithm with no payload, and with a payload that is not decodable base64
# (a lone 'A' is one sixth-bit group, not a whole quantum). These are the only two ways the key
# MATERIAL can fail -- see the accepted bodies below for what does NOT fail.
_EMPTY_PAYLOAD_BODY = 'ssh-rsa '
_UNDECODABLE_BODY = 'ssh-rsa A'

# ACCEPTED by real AWS, and asserted as such: the key material is not parsed as a key.
#   * a payload truncated mid-modulus (still 4-aligned base64, so it decodes to a byte string that
#     is not a complete RSA key),
#   * an RSA payload declared as ssh-ed25519 -- the declared algorithm is NOT cross-checked
#     against the algorithm name embedded in the decoded blob,
#   * the ecdsa- family, accepted by PREFIX: even an ecdsa-sha2-<not a curve> label goes through.
_TRUNCATED_BODY = f'ssh-rsa {_KEY_PAYLOAD[:64]}'
_MISLABELLED_BODY = f'ssh-ed25519 {_KEY_PAYLOAD}'
_ECDSA_LABEL_BODY = f'ecdsa-sha2-nistp256 {_KEY_PAYLOAD}'

_GONE_TIMEOUT_S = 300.0
_INTERVAL_S = 15.0


def _err(fn):
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message')
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportSshPublicKey refuses unsupported algorithm names, empty or undecodable payloads and
    duplicates, accepts unparsed key material verbatim, and scopes each key id to one user.
    """
    # The server is never started; DeleteServer (not StopServer) is what stops endpoint billing.
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

    # Registered before anything else so the billable endpoint is reaped last (on_cleanup is LIFO).
    ctx.on_cleanup(_reap_server)

    # The users' role: created here, trusted by Transfer, with no permissions attached.
    iam = ctx.client('iam')
    role_name = ctx.unique_name('sim2real-behav-keyrole-')
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            'Version': '2012-10-17',
            'Statement': [{'Effect': 'Allow', 'Principal': {'Service': 'transfer.amazonaws.com'},
                           'Action': 'sts:AssumeRole'}]}),
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])['Role']['Arn']
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    user_a = ctx.unique_name('sim2realbehavkeya')
    user_b = ctx.unique_name('sim2realbehavkeyb')
    for name in (user_a, user_b):
        tf.create_user(ServerId=server_id, UserName=name, Role=role,
                       HomeDirectory='/sim2real-behav', HomeDirectoryType='PATH',
                       Tags=[{'Key': 'sim2real', 'Value': CHECK}])
        ctx.on_cleanup(
            lambda _n=name: tf.delete_user(ServerId=server_id, UserName=_n))

    # --- positive: the captured body is accepted and fully described -----------------------
    imported = tf.import_ssh_public_key(
        ServerId=server_id, UserName=user_a, SshPublicKeyBody=_GOOD_BODY)
    key_id = imported['SshPublicKeyId']
    assert _KEY_ID_RE.match(key_id), f"SshPublicKeyId {key_id!r} violates ^key-[0-9a-f]{{17}}$"
    assert imported['ServerId'] == server_id, imported
    assert imported['UserName'] == user_a, imported

    user = tf.describe_user(ServerId=server_id, UserName=user_a)['User']
    keys = user['SshPublicKeys']
    assert len(keys) == 1, f"user {user_a} must have exactly one key, got {keys!r}"
    stored = keys[0]
    assert stored['SshPublicKeyId'] == key_id, stored
    assert stored['DateImported'], (
        f"DateImported is a REQUIRED member of SshPublicKey and must be populated: {stored!r}")
    # The body must round-trip: the base64 payload is what the server will authenticate against,
    # so a store that keeps only a hash or a truncation is a defect.
    assert _KEY_PAYLOAD in stored['SshPublicKeyBody'], (
        f"the stored SshPublicKeyBody does not contain the imported payload: "
        f"{stored['SshPublicKeyBody']!r}")
    # The round-tripped payload must still decode to the SSH wire format naming the declared
    # algorithm.
    blob = base64.b64decode(stored['SshPublicKeyBody'].split()[1], validate=True)
    name_len = int.from_bytes(blob[:4], 'big')
    assert blob[4:4 + name_len] == b'ssh-rsa', (
        f"the stored key body does not decode to an ssh-rsa wire-format key: "
        f"{blob[4:4 + name_len]!r}")

    listed = {u['UserName']: u for u in tf.list_users(ServerId=server_id)['Users']}
    assert listed[user_a].get('SshPublicKeyCount') == 1, (
        f"ListUsers must project SshPublicKeyCount 1 for {user_a}, got "
        f"{listed[user_a].get('SshPublicKeyCount')!r}")
    assert listed[user_b].get('SshPublicKeyCount') == 0, (
        f"the key must be scoped to {user_a}; {user_b} reports SshPublicKeyCount "
        f"{listed[user_b].get('SshPublicKeyCount')!r}")

    def _keys(name):
        return {
            k['SshPublicKeyId']
            for k in tf.describe_user(ServerId=server_id, UserName=name)['User']['SshPublicKeys']
        }

    # --- negatives, one broken thing each -------------------------------------------------
    code_dup, msg_dup = _err(lambda: tf.import_ssh_public_key(
        ServerId=server_id, UserName=user_a, SshPublicKeyBody=_GOOD_BODY))
    assert code_dup == 'ResourceExistsException', (
        f"re-importing an identical key body must raise ResourceExistsException (modeled on "
        f"ImportSshPublicKey), got {code_dup!r}: {msg_dup!r}")
    assert msg_dup == 'Public key already exists', (
        f"unexpected duplicate-key diagnostic: {msg_dup!r}")
    assert _keys(user_a) == {key_id}, (
        f"the duplicate import must not add a second key: {_keys(user_a)}")

    # The SAME body with a trailing newline is still the same key: duplicate detection strips
    # surrounding whitespace before comparing (the smithy pattern permits the trailing \s*), so an
    # emulator keying its store on the raw bytes would accept this and hold the key twice.
    code_nl, msg_nl = _err(lambda: tf.import_ssh_public_key(
        ServerId=server_id, UserName=user_a, SshPublicKeyBody=_GOOD_BODY + '\n'))
    assert code_nl == 'ResourceExistsException', (
        f"an already-imported body with only a trailing newline added is still a duplicate, got "
        f"{code_nl!r}: {msg_nl!r}")
    assert msg_nl == 'Public key already exists', (
        f"unexpected duplicate-key diagnostic for the whitespace variant: {msg_nl!r}")
    assert _keys(user_a) == {key_id}, (
        f"the whitespace-variant import added a second key: {_keys(user_a)}")

    # The key-format boundary: four ways to fail it, all refused, all with the SAME message.
    bad_bodies = {
        'unsupported algorithm name (ssh-dss)': _UNSUPPORTED_ALGO_BODY,
        'unknown algorithm name (ssh-foo)': _UNKNOWN_ALGO_BODY,
        'empty base64 payload': _EMPTY_PAYLOAD_BODY,
        'undecodable base64 payload': _UNDECODABLE_BODY,
    }
    for label, body in bad_bodies.items():
        code_bad, msg_bad = _err(lambda _b=body: tf.import_ssh_public_key(
            ServerId=server_id, UserName=user_a, SshPublicKeyBody=_b))
        assert code_bad == 'InvalidRequestException', (
            f"a key body with an {label} must be rejected with InvalidRequestException, got "
            f"{code_bad!r}: {msg_bad!r}")
        assert msg_bad == _BAD_KEY_MSG, (
            f"real Transfer answers every key-format failure with {_BAD_KEY_MSG!r}; for an "
            f"{label} it gave {msg_bad!r}")
        assert _keys(user_a) == {key_id}, (
            f"the body with an {label} was stored anyway: {_keys(user_a)}")
    # The format refusal is a DIFFERENT failure from the duplicate one, and only the duplicate
    # carries its own message -- an emulator with one generic key error fails here.
    assert msg_dup != _BAD_KEY_MSG, (msg_dup, _BAD_KEY_MSG)

    # --- the other side of that boundary: bodies real AWS ACCEPTS ---------------------------
    # Each is imported, asserted to be stored VERBATIM under a fresh id, and deleted immediately so
    # the cross-user leg below still sees exactly one key on user_a.
    accepted_bodies = {
        'a payload truncated mid-modulus': _TRUNCATED_BODY,
        'an RSA payload declared as ssh-ed25519': _MISLABELLED_BODY,
        'an ecdsa- algorithm label': _ECDSA_LABEL_BODY,
    }
    for label, body in accepted_bodies.items():
        extra = tf.import_ssh_public_key(
            ServerId=server_id, UserName=user_a, SshPublicKeyBody=body)
        extra_id = extra['SshPublicKeyId']
        assert _KEY_ID_RE.match(extra_id), f"{label}: bad SshPublicKeyId {extra_id!r}"
        assert extra_id != key_id, (
            f"{label}: a distinct body must get a distinct key id, got {extra_id!r}")
        assert _keys(user_a) == {key_id, extra_id}, (
            f"{label} was accepted but not stored: {_keys(user_a)}")
        got_body = [
            k['SshPublicKeyBody']
            for k in tf.describe_user(ServerId=server_id, UserName=user_a)['User']['SshPublicKeys']
            if k['SshPublicKeyId'] == extra_id][0]
        assert got_body == body, (
            f"{label}: real Transfer stores the body verbatim without normalising or "
            f"re-encoding it; sent {body!r}, got {got_body!r}")
        tf.delete_ssh_public_key(
            ServerId=server_id, UserName=user_a, SshPublicKeyId=extra_id)
        assert _keys(user_a) == {key_id}, (
            f"{label}: DeleteSshPublicKey did not remove {extra_id}: {_keys(user_a)}")

    # Key ids are scoped to a user, not to the server.
    code_cross, msg_cross = _err(lambda: tf.delete_ssh_public_key(
        ServerId=server_id, UserName=user_b, SshPublicKeyId=key_id))
    assert code_cross == 'ResourceNotFoundException', (
        f"deleting {user_a}'s key id under {user_b} must raise ResourceNotFoundException, got "
        f"{code_cross!r}: {msg_cross!r}")
    assert msg_cross == 'Unknown public key ID', (
        f"unexpected cross-user delete diagnostic: {msg_cross!r}")
    assert _keys(user_a) == {key_id}, (
        f"the cross-user delete removed {user_a}'s key: {_keys(user_a)}")

    # --- control: the same delete, correctly scoped, works --------------------------------
    tf.delete_ssh_public_key(ServerId=server_id, UserName=user_a, SshPublicKeyId=key_id)
    after = tf.describe_user(ServerId=server_id, UserName=user_a)['User']
    assert after['SshPublicKeys'] == [], (
        f"after DeleteSshPublicKey the key list must be empty, got {after['SshPublicKeys']!r}")
    final_count = {u['UserName']: u.get('SshPublicKeyCount')
                   for u in tf.list_users(ServerId=server_id)['Users']}[user_a]
    assert final_count == 0, (
        f"ListUsers must project SshPublicKeyCount 0 for {user_a} after the delete, got "
        f"{final_count!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
