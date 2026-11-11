"""native-cql-round-trip."""
from __future__ import annotations

import socket
import ssl
import struct
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "native-cql-round-trip"
GROUP = "native-protocol"
SERVICES = ["keyspaces"]

# ===== inlined stdlib CQL v4 binary-protocol client =====
#
# Amazon Keyspaces has no AWS-JSON data plane: rows only go in and come out over the Cassandra
# native protocol on port 9142. This client needs no third-party Cassandra driver: it is written
# against `socket` + `ssl` + `struct` only, and works against
# cassandra.us-west-2.amazonaws.com:9142, which answers a v4 OPTIONS frame with
# PROTOCOL_VERSIONS 3/v3,4/v4,5/v5-beta and CQL_VERSION 3.4.4 and authenticates SASL PLAIN
# against an IAM service-specific credential. No VPC and no third-party package are needed.

_V_REQ = 0x04       # request frame version
_V_RESP = 0x84      # response frame version (high bit set)

_OP_ERROR = 0x00
_OP_STARTUP = 0x01
_OP_AUTHENTICATE = 0x03
_OP_OPTIONS = 0x05
_OP_SUPPORTED = 0x06
_OP_QUERY = 0x07
_OP_RESULT = 0x08
_OP_AUTH_RESPONSE = 0x0F
_OP_AUTH_SUCCESS = 0x10

_CL_LOCAL_QUORUM = 0x0006
_CL_LOCAL_ONE = 0x000A

_ERR_BAD_CREDENTIALS = 0x0100

_CQL_PORT = 9142
_CQL_VERSION = "3.4.4"
_PASSWORD_AUTHENTICATOR = "org.apache.cassandra.auth.PasswordAuthenticator"

_TYPE_NAMES = {
    0x0001: "ascii", 0x0002: "bigint", 0x0003: "blob", 0x0004: "boolean",
    0x0005: "counter", 0x0006: "decimal", 0x0007: "double", 0x0008: "float",
    0x0009: "int", 0x000B: "timestamp", 0x000C: "uuid", 0x000D: "varchar",
    0x000E: "varint", 0x000F: "timeuuid", 0x0010: "inet", 0x0011: "date",
    0x0012: "time", 0x0013: "smallint", 0x0014: "tinyint",
}

# Marks a failure of the CQL endpoint itself: nothing answering on 9142 is a data-plane failure of
# the target, not a network problem of the caller.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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

    def string_multimap(self) -> dict:
        return {self.string(): [self.string() for _ in range(self.short())]
                for _ in range(self.short())}


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


def _read_type(r: _Reader) -> str:
    tid = r.short()
    if tid == 0x0000:
        return f"custom:{r.string()}"
    if tid in (0x0020, 0x0022):
        return f"{'list' if tid == 0x0020 else 'set'}<{_read_type(r)}>"
    if tid == 0x0021:
        key = _read_type(r)
        return f"map<{key},{_read_type(r)}>"
    return _TYPE_NAMES.get(tid, f"unknown-0x{tid:04X}")


def _decode(type_name: str, raw):
    """Cassandra's cell encodings, for the two types this check's table declares."""
    if raw is None:
        return None
    if type_name in ("varchar", "ascii"):
        return raw.decode()
    if type_name == "int":
        return struct.unpack(">i", raw)[0]
    if type_name == "boolean":
        return raw[0] != 0
    return raw


def _read_metadata(r: _Reader):
    flags = r.int()
    count = r.int()
    paging_state = r.bytes_() if flags & 0x0002 else None
    if flags & 0x0004:                                  # No_metadata
        return [], paging_state
    if flags & 0x0001:                                  # Global_tables_spec
        r.string()
        r.string()
    cols = []
    for _ in range(count):
        if not flags & 0x0001:
            r.string()
            r.string()
        cols.append((r.string(), _read_type(r)))
    return cols, paging_state


class _Rows:
    def __init__(self, columns, rows, paging_state):
        self.columns = columns
        self.rows = rows
        self.paging_state = paging_state


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
            # Verification ON, with the system trust store.
            self.sock = _tls_context().wrap_socket(raw, server_hostname=host)
        except OSError as exc:
            # The target published this endpoint; failing to answer on it is the target's
            # fidelity failure, not this runner's environment.
            raise AssertionError(
                f"{DATAPLANE_MARKER}: nothing accepted a TLS CQL connection on "
                f"{host}:{_CQL_PORT}: {type(exc).__name__}: {exc}") from exc
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
                    f"{DATAPLANE_MARKER}: the CQL connection to {self.host} closed mid-frame "
                    f"after {len(out)} of {n} bytes")
            out += chunk
        return out

    def request(self, opcode: int, body: bytes = b"", *, raise_on_error: bool = True):
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
                err = self._error(payload)
                if raise_on_error:
                    raise err
                return _OP_ERROR, err
            return op, payload

    @staticmethod
    def _error(payload: bytes) -> _CqlError:
        r = _Reader(payload)
        return _CqlError(r.int(), r.string())

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

    def query(self, cql: str, consistency: int = _CL_LOCAL_QUORUM, raise_on_error: bool = True):
        body = _pack_long_string(cql) + struct.pack(">HB", consistency, 0)
        return self._result(self.request(_OP_QUERY, body, raise_on_error=raise_on_error))

    @staticmethod
    def _result(answer):
        op, payload = answer
        if op == _OP_ERROR:
            return payload                              # a _CqlError the caller asked to inspect
        assert op == _OP_RESULT, f"expected RESULT (0x08), got opcode 0x{op:02X}"
        r = _Reader(payload)
        kind = r.int()
        if kind == 1:
            return None                                 # Void
        if kind in (3, 5):
            return {"kind": kind}                        # Set_keyspace / Schema_change
        assert kind == 2, f"unexpected RESULT kind {kind!r}"
        columns, paging_state = _read_metadata(r)
        rows = [[_decode(columns[c][1], r.bytes_()) for c in range(len(columns))]
                for _ in range(r.int())]
        return _Rows(columns, rows, paging_state)


# ===== end inlined CQL client =====


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


def _wait_keyspace_visible(ksc, keyspace: str, timeout_s: float = 180.0) -> None:
    """CreateKeyspace is asynchronous: measured, CreateTable answered
    `ResourceNotFoundException: Keyspace ... does not exist` when issued immediately after."""
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
    """Poll GetTable to ACTIVE, tolerating the `unconfigured table` window measured right after
    CreateTable returned. The budget is generous on purpose -- under-declaring a wait is what
    manufactures `Check timed out` MISMATCHes."""
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


def _cql_credential(ctx, scenario: str) -> tuple:
    """A throwaway IAM user holding a cassandra.amazonaws.com service-specific credential --
    the only thing Keyspaces' SASL PLAIN authenticator accepts, and it attaches to a user."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-c4cql-")[:64]
    ctx.on_cleanup(lambda: _delete_cql_user_quietly(iam, user))
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": scenario}])
    iam.put_user_policy(
        UserName=user, PolicyName="sim2real-cassandra",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                       '"Action":["cassandra:Select","cassandra:Modify"],"Resource":["*"]}]}')
    cred = iam.create_service_specific_credential(
        UserName=user, ServiceName="cassandra.amazonaws.com")["ServiceSpecificCredential"]
    return user, cred["ServiceUserName"], cred["ServicePassword"]


def _connect(ctx, username: str, password: str, budget_s: float = 300.0) -> _CqlConnection:
    """Open one authenticated connection, retrying ONLY on the credential-propagation refusal
    (error 0x0100). IAM exposes no condition that says the credential is usable yet, so this
    bounded retry IS the wait; any other error code is raised rather than retried away."""
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
            time.sleep(2)
    raise AssertionError(
        f"no CQL connection to {host} authenticated within {budget_s}s (last {last!r})")


def _verified_teardown(ksc, iam, keyspace: str, table: str, user: str,
                       timeout_s: float = 420.0) -> None:
    """Delete table -> keyspace -> IAM user INLINE, then prove each is gone.

    `on_cleanup` runs on a daemon thread joined with a 60 s cap and, by its own docstring, NEVER
    affects the verdict -- so a chain that exceeds it is cut mid-way, the rest leaks, and the check
    still reports PASS. Ordering matters and cannot be rushed: measured, DeleteKeyspace answers
    `ConflictException: ... or a table under it is currently being created or deleted` when issued
    immediately after DeleteTable, so the table's disappearance is polled first.
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
    # DeleteKeyspace is asynchronous too: measured, GetKeyspace still returned the keyspace
    # immediately after DeleteKeyspace was accepted. Poll it out of existence rather than
    # asserting on the first read.
    while time.monotonic() < deadline:
        try:
            ksc.get_keyspace(keyspaceName=keyspace)
        except ClientError as exc:
            assert exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException", (
                f"GetKeyspace on the deleted keyspace answered "
                f"{exc.response.get('Error', {}).get('Code')!r}, expected "
                f"ResourceNotFoundException")
            expected = f"Keyspace {keyspace} does not exist"
            assert exc.response["Error"]["Message"] == expected, (
                f"GetKeyspace on the deleted keyspace answered message "
                f"{exc.response['Error']['Message']!r}, expected {expected!r}")
            break
        time.sleep(5.0)
    else:
        raise AssertionError(
            f"keyspace {keyspace!r} was still listed {timeout_s}s after DeleteKeyspace "
            f"(last conflict {last!r})")

    _delete_cql_user_quietly(iam, user)
    try:
        iam.get_user(UserName=user)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    else:
        raise AssertionError(f"the throwaway CQL IAM user {user!r} still exists after cleanup")


_SCENARIO = "native-cql-round-trip"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """A table created through the control plane serves CQL over Keyspaces' native protocol on
    port 9142: an INSERT followed by an independent SELECT round-trips the value."""
    ksc = ctx.client("keyspaces")
    keyspace = ctx.unique_name("sim2real_c4cql_")
    table = "rows"
    qualified = f"{keyspace}.{table}"

    user, cql_user, cql_password = _cql_credential(ctx, _SCENARIO)

    # Registered BEFORE the create. A keyspace holding tables cannot be deleted, and cleanup is
    # LIFO, so the table registration below runs first.
    ctx.on_cleanup(lambda: _delete_keyspace_quietly(ksc, keyspace))
    ksc.create_keyspace(keyspaceName=keyspace,
                        tags=[{"key": "sim2real", "value": _SCENARIO}])
    _wait_keyspace_visible(ksc, keyspace)

    ctx.on_cleanup(lambda: _delete_table_quietly(ksc, keyspace, table))
    ksc.create_table(
        keyspaceName=keyspace, tableName=table,
        schemaDefinition={
            "allColumns": [{"name": "pk", "type": "text"}, {"name": "val", "type": "text"}],
            "partitionKeys": [{"name": "pk"}],
        },
        tags=[{"key": "sim2real", "value": _SCENARIO}])
    _wait_table_active(ksc, keyspace, table)

    conn = _connect(ctx, cql_user, cql_password)
    ctx.on_cleanup(conn.close)

    conn.query(f"INSERT INTO {qualified} (pk, val) VALUES ('row1', 'hello-cql')")

    value = None
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        result = conn.query(f"SELECT val FROM {qualified} WHERE pk = 'row1'",
                            consistency=_CL_LOCAL_ONE)
        if result.rows:
            value = result.rows[0][0]
            break
        time.sleep(1.0)
    assert value == "hello-cql", (
        f"an independent SELECT on the row this check INSERTed must round-trip the value, "
        f"got {value!r}")

    # --- verified inline teardown, under this check's own budget rather than the 60 s that bounds
    # the `on_cleanup` chain; those registrations stay as the failure-path net.
    conn.close()
    _verified_teardown(ksc, ctx.client("iam"), keyspace, table, user)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
