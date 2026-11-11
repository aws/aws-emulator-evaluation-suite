"""native-cql-ttl-expiry."""
from __future__ import annotations

import socket
import ssl
import struct
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "native-cql-ttl-expiry"
GROUP = "native-protocol"
SERVICES = ["keyspaces"]

# ===== inlined stdlib CQL v4 binary-protocol client (self-contained) =====
# `cassandra-driver` and `cassandra-sigv4` are NOT in SimParity's dependency set (it declares click,
# requests, botocore, boto3, cbor2 and nothing else), so importing them here is dead on every
# target. This check instead speaks CQL v4 directly over `socket` + `ssl` + `struct`, and
# authenticates SASL PLAIN against a throwaway IAM user's service-specific credential. Only the
# frames this check needs (STARTUP/AUTHENTICATE/AUTH_RESPONSE/AUTH_SUCCESS and QUERY/RESULT with
# text columns) are implemented; PREPARE/EXECUTE and paging are not needed here.

_V_REQ = 0x04
_V_RESP = 0x84

_OP_ERROR = 0x00
_OP_STARTUP = 0x01
_OP_AUTHENTICATE = 0x03
_OP_QUERY = 0x07
_OP_RESULT = 0x08
_OP_AUTH_RESPONSE = 0x0F
_OP_AUTH_SUCCESS = 0x10

_CL_LOCAL_QUORUM = 0x0006
_ERR_BAD_CREDENTIALS = 0x0100

_CQL_PORT = 9142
_CQL_VERSION = "3.4.4"


class _CqlError(Exception):
    """An ERROR frame. Carries the protocol error code so assertions can name it exactly."""

    def __init__(self, code: int, message: str):
        super().__init__(f"CQL error 0x{code:04X}: {message}")
        self.code = code
        self.message = message


class _Reader:
    """Sequential reader over one frame body. Raises rather than returning short data: a single
    wrong length prefix desynchronises the stream, and silently truncating hides that."""

    def __init__(self, buf: bytes):
        self.b = buf
        self.i = 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise AssertionError(
                f"CQL frame body truncated: wanted {n} bytes at offset {self.i} of {len(self.b)}")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def short(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def int(self) -> int:
        return struct.unpack(">i", self.take(4))[0]

    def string(self) -> str:
        return self.take(self.short()).decode()

    def bytes_(self):
        n = self.int()
        return None if n < 0 else self.take(n)


def _pack_string(s: str) -> bytes:
    raw = s.encode()
    return struct.pack(">H", len(raw)) + raw


def _pack_long_string(s: str) -> bytes:
    raw = s.encode()
    return struct.pack(">i", len(raw)) + raw


def _pack_bytes(v) -> bytes:
    if v is None:
        return struct.pack(">i", -1)
    return struct.pack(">i", len(v)) + v


def _tls_context():
    """An encrypting TLS context that does not verify the server's identity."""
    return ssl._create_unverified_context()


class _CqlConnection:
    """One TLS CQL v4 connection: 9-byte framing, SASL PLAIN handshake, QUERY."""

    def __init__(self, host: str, timeout_s: float = 60.0, *, port: int = _CQL_PORT):
        self.host = host
        self._stream = 0
        try:
            raw = socket.create_connection((host, port), timeout=timeout_s)
            self.sock = _tls_context().wrap_socket(raw, server_hostname=host)
        except OSError as exc:
            raise AssertionError(
                f"nothing accepted a TLS CQL connection on {host}:{_CQL_PORT}: "
                f"{type(exc).__name__}: {exc}") from exc
        self.sock.settimeout(timeout_s)
        self.authenticator = None

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _recvn(self, n: int) -> bytes:
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise AssertionError(
                    f"the CQL connection to {self.host} closed mid-frame after "
                    f"{len(out)} of {n} bytes")
            out += chunk
        return out

    def request(self, opcode: int, body: bytes = b""):
        self._stream = (self._stream + 1) % 30000
        sent = self._stream
        self.sock.sendall(struct.pack(">BBhBi", _V_REQ, 0, sent, opcode, len(body)) + body)
        while True:
            version, flags, stream, op, length = struct.unpack(">BBhBi", self._recvn(9))
            assert version == _V_RESP, (
                f"expected a v4 response frame (0x{_V_RESP:02X}), got 0x{version:02X} -- the "
                f"server did not answer in the protocol version it advertised")
            payload = self._recvn(length) if length else b""
            if stream != sent:
                continue                                # a server EVENT, not our reply
            if op == _OP_ERROR:
                r = _Reader(payload)
                raise _CqlError(r.int(), r.string())
            return op, payload

    def authenticate(self, username: str, password: str) -> str:
        body = struct.pack(">H", 1) + _pack_string("CQL_VERSION") + _pack_string(_CQL_VERSION)
        op, payload = self.request(_OP_STARTUP, body)
        assert op == _OP_AUTHENTICATE, (
            f"STARTUP was answered with opcode 0x{op:02X}, expected AUTHENTICATE (0x03) -- a "
            f"cluster that requires credentials must challenge before it is READY")
        self.authenticator = _Reader(payload).string()
        token = b"\x00" + username.encode() + b"\x00" + password.encode()
        op, _ = self.request(_OP_AUTH_RESPONSE, _pack_bytes(token))
        assert op == _OP_AUTH_SUCCESS, (
            f"AUTH_RESPONSE was answered with opcode 0x{op:02X}, expected AUTH_SUCCESS (0x10)")
        return self.authenticator

    def query(self, cql: str) -> list[tuple]:
        """Issue a CQL statement with no bound parameters; decode every result column as text
        (this check's schema declares only `text` columns, so no wider type table is needed)."""
        body = _pack_long_string(cql) + struct.pack(">HB", _CL_LOCAL_QUORUM, 0)
        op, payload = self.request(_OP_QUERY, body)
        assert op == _OP_RESULT, f"expected RESULT (0x08), got opcode 0x{op:02X}"
        r = _Reader(payload)
        kind = r.int()
        if kind != 2:                                   # Void / Set_keyspace / Schema_change
            return []
        flags = r.int()
        count = r.int()
        if flags & 0x0002:                              # Has_more_pages
            r.bytes_()
        if not flags & 0x0004:                           # not No_metadata
            if flags & 0x0001:                            # Global_tables_spec
                r.string()
                r.string()
            for _ in range(count):
                if not flags & 0x0001:
                    r.string()
                    r.string()
                r.string()                                 # column name
                r.short()                                  # column type id; all text here
        rows = []
        for _ in range(r.int()):
            row = []
            for _ in range(count):
                raw = r.bytes_()
                row.append(raw.decode() if raw is not None else None)
            rows.append(tuple(row))
        return rows

# ===== end inlined CQL client =====


_SCENARIO = "native-cql-ttl-expiry"


def _delete_keyspace_quietly(ksc, keyspace: str) -> None:
    try:
        ksc.delete_keyspace(keyspaceName=keyspace)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_table_quietly(ksc, keyspace: str, table: str) -> None:
    try:
        ksc.delete_table(keyspaceName=keyspace, tableName=table)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _delete_cql_user_quietly(iam, user: str) -> None:
    """A service-specific credential and an inline policy both block DeleteUser."""
    try:
        for cred in iam.list_service_specific_credentials(
                UserName=user,
                ServiceName="cassandra.amazonaws.com").get("ServiceSpecificCredentials", []):
            iam.delete_service_specific_credential(
                UserName=user,
                ServiceSpecificCredentialId=cred["ServiceSpecificCredentialId"])
        for name in iam.list_user_policies(UserName=user).get("PolicyNames", []):
            iam.delete_user_policy(UserName=user, PolicyName=name)
        iam.delete_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _cql_credential(ctx, scenario: str) -> tuple:
    """A throwaway IAM user holding a cassandra.amazonaws.com service-specific credential.

    Keyspaces' native protocol authenticates SASL PLAIN against exactly this, and it attaches to
    an IAM *user*, so a user is unavoidable for a caller holding role credentials.
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-c4ttl-")[:64]
    # Registered BEFORE the create so a failure in between cannot leak a principal.
    ctx.on_cleanup(lambda: _delete_cql_user_quietly(iam, user))
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": scenario}])
    iam.put_user_policy(
        UserName=user, PolicyName="sim2real-cassandra",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                       '"Action":["cassandra:Select","cassandra:Modify"],"Resource":["*"]}]}')
    cred = iam.create_service_specific_credential(
        UserName=user, ServiceName="cassandra.amazonaws.com")["ServiceSpecificCredential"]
    return user, cred["ServiceUserName"], cred["ServicePassword"]


def _wait_keyspace_visible(ksc, keyspace: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ksc.get_keyspace(keyspaceName=keyspace)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            time.sleep(3.0)
    raise AssertionError(f"keyspace {keyspace!r} never became visible within {timeout_s}s")


def _wait_table_active(ksc, keyspace: str, table: str, timeout_s: float = 600.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ksc.get_table(keyspaceName=keyspace, tableName=table)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
            time.sleep(3.0)
            continue
        if last.get("status") == "ACTIVE":
            return last
        time.sleep(3.0)
    raise AssertionError(
        f"table {keyspace}.{table} never reached ACTIVE within {timeout_s}s (last {last!r})")


def _connect(ctx, username: str, password: str, budget_s: float = 300.0) -> _CqlConnection:
    """Open one authenticated connection, retrying ONLY on the credential-propagation refusal.

    IAM exposes no condition that says "this service-specific credential is now usable", so the
    bounded retry on error 0x0100 IS the wait.
    """
    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", _CQL_PORT)
    deadline = time.monotonic() + budget_s
    last = None
    while time.monotonic() < deadline:
        conn = _CqlConnection(host, port=port)
        try:
            conn.authenticate(username, password)
            return conn
        except _CqlError as exc:
            if exc.code != _ERR_BAD_CREDENTIALS:
                raise
            last = exc
            conn.close()
            time.sleep(8.0)
    raise AssertionError(f"no CQL connection to {host} authenticated within {budget_s}s (last {last!r})")


def _wait_row_expired(conn: _CqlConnection, table: str, key: str, timeout_s: float = 30.0) -> list:
    """Poll SELECT until the whole row stops being returned; never a bare sleep. A row written
    with `USING TTL` carries that TTL on every non-key cell, so once all of them expire the row
    itself -- which has no live cell left -- disappears from SELECT entirely."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = conn.query(f"SELECT val FROM {table} WHERE pk = '{key}'")
        if not last:
            return last
        time.sleep(1.0)
    raise AssertionError(f"row with a 3s TTL was still present {timeout_s}s after insert: {last!r}")


def _verified_teardown(ksc, iam, keyspace: str, table: str, user: str,
                        timeout_s: float = 420.0) -> None:
    """Delete table -> keyspace -> IAM user INLINE, then prove each is gone.

    `on_cleanup` runs on a daemon thread joined with a 60s cap and never affects the verdict, so a
    chain that exceeds it is cut mid-way and leaks while the check still reports PASS -- this
    teardown must be proven here instead, with the on_cleanup registrations left as the failure
    net for the case where the body raises before reaching this point.
    """
    deadline = time.monotonic() + timeout_s
    _delete_table_quietly(ksc, keyspace, table)
    while time.monotonic() < deadline:
        try:
            ksc.get_table(keyspaceName=keyspace, tableName=table)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                break
            raise
        time.sleep(5.0)
    else:
        raise AssertionError(f"table {keyspace}.{table} was still listed after {timeout_s}s")

    last = None
    while time.monotonic() < deadline:
        try:
            ksc.delete_keyspace(keyspaceName=keyspace)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                break
            if code != "ConflictException":
                raise
            last = exc
            time.sleep(5.0)
            continue
        break
    while time.monotonic() < deadline:
        try:
            ksc.get_keyspace(keyspaceName=keyspace)
        except ClientError as exc:
            assert exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException", (
                f"GetKeyspace on the deleted keyspace answered "
                f"{exc.response.get('Error', {}).get('Code')!r}, expected ResourceNotFoundException")
            expected = f"Keyspace {keyspace} does not exist"
            assert exc.response["Error"]["Message"] == expected, (
                f"GetKeyspace on the deleted keyspace answered message "
                f"{exc.response['Error']['Message']!r}, expected {expected!r}")
            break
        time.sleep(5.0)
    else:
        raise AssertionError(
            f"keyspace {keyspace!r} was still listed {timeout_s}s after DeleteKeyspace (last conflict {last!r})")

    _delete_cql_user_quietly(iam, user)
    try:
        iam.get_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    else:
        raise AssertionError(f"the throwaway CQL IAM user {user!r} still exists after cleanup")


# timing:real-time — ttl: 3 s https://docs.aws.amazon.com/keyspaces/latest/devguide/TTL.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A row written with a short CQL-level TTL becomes unreadable via SELECT once the TTL
    elapses, and the row's deletion, keyspace deletion and throwaway IAM credential are each
    independently proven gone at teardown."""
    ksc = ctx.client("keyspaces")
    iam = ctx.client("iam")
    keyspace = ctx.unique_name("sim2real_c4ttl_")
    table = "rows"
    qualified = f"{keyspace}.{table}"

    user, cql_user, cql_password = _cql_credential(ctx, _SCENARIO)

    # Registered BEFORE the create. A keyspace holding tables cannot be deleted, and cleanup is
    # LIFO, so the table registration below runs first.
    ctx.on_cleanup(lambda: _delete_keyspace_quietly(ksc, keyspace))
    ksc.create_keyspace(keyspaceName=keyspace, tags=[{"key": "sim2real", "value": _SCENARIO}])
    _wait_keyspace_visible(ksc, keyspace)

    ctx.on_cleanup(lambda: _delete_table_quietly(ksc, keyspace, table))
    ksc.create_table(
        keyspaceName=keyspace, tableName=table,
        schemaDefinition={
            "allColumns": [{"name": "pk", "type": "text"}, {"name": "val", "type": "text"}],
            "partitionKeys": [{"name": "pk"}],
        },
        ttl={"status": "ENABLED"},
        tags=[{"key": "sim2real", "value": _SCENARIO}])
    described = _wait_table_active(ksc, keyspace, table)
    assert described.get("ttl", {}).get("status") == "ENABLED", (
        f"the table reports ttl {described.get('ttl')!r}; INSERT ... USING TTL below needs it ENABLED")

    conn = _connect(ctx, cql_user, cql_password)
    ctx.on_cleanup(conn.close)

    conn.query(f"INSERT INTO {qualified} (pk, val) VALUES ('ttl-row', 'gone-soon') USING TTL 3")

    rows = conn.query(f"SELECT val FROM {qualified} WHERE pk = 'ttl-row'")
    assert rows and rows[0][0] == "gone-soon", (
        f"row must be readable before its TTL elapses, got {rows!r}")

    _wait_row_expired(conn, qualified, "ttl-row")

    conn.close()
    _verified_teardown(ksc, iam, keyspace, table, user)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
