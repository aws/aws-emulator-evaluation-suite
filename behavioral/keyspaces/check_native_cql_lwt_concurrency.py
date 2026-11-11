"""native-cql-lwt-concurrency."""
from __future__ import annotations

import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "native-cql-lwt-concurrency"
GROUP = "native-protocol"
SERVICES = ["keyspaces"]

# A standard-library CQL v4 binary-protocol client.
#
# Amazon Keyspaces has no AWS-JSON data plane for rows: the Cassandra native protocol on port
# 9142 is the only way in or out, and the Cassandra drivers are not declared dependencies. This
# client speaks the wire protocol directly over `socket` + `ssl` + `struct`, authenticating with
# SASL PLAIN against an IAM service-specific credential at cassandra.<region>.amazonaws.com:9142.

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

_TYPE_NAMES = {0x0004: "boolean", 0x000D: "varchar"}


class _CqlError(Exception):
    """An ERROR frame. Carries the protocol error code so assertions can name it exactly."""

    def __init__(self, code: int, message: str):
        super().__init__(f"CQL error 0x{code:04X}: {message}")
        self.code = code
        self.message = message


class _Reader:
    """Sequential reader over one frame body. Raises rather than returning short data."""

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


def _decode(type_name: str, raw):
    if raw is None:
        return None
    if type_name == "varchar":
        return raw.decode()
    if type_name == "boolean":
        return raw[0] != 0
    return raw


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
                    f"the CQL connection to {self.host} closed mid-frame after {len(out)} of {n} bytes")
            out += chunk
        return out

    def request(self, opcode: int, body: bytes = b"", *, raise_on_error: bool = True):
        self._stream = (self._stream + 1) % 30000
        sent = self._stream
        self.sock.sendall(struct.pack(">BBhBi", _V_REQ, 0, sent, opcode, len(body)) + body)
        while True:
            version, flags, stream, op, length = struct.unpack(">BBhBi", self._recvn(9))
            assert version == _V_RESP, (
                f"expected a v4 response frame (0x{_V_RESP:02X}), got 0x{version:02X}")
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

    def authenticate(self, username: str, password: str) -> None:
        body = struct.pack(">H", 1) + _pack_string("CQL_VERSION") + _pack_string(_CQL_VERSION)
        op, payload = self.request(_OP_STARTUP, body)
        assert op == _OP_AUTHENTICATE, (
            f"STARTUP was answered with opcode 0x{op:02X}, expected AUTHENTICATE (0x03)")
        self.authenticator = _Reader(payload).string()
        token = b"\x00" + username.encode() + b"\x00" + password.encode()
        op, _ = self.request(_OP_AUTH_RESPONSE, _pack_bytes(token))
        assert op == _OP_AUTH_SUCCESS, (
            f"AUTH_RESPONSE was answered with opcode 0x{op:02X}, expected AUTH_SUCCESS (0x10)")

    def query(self, cql: str, consistency: int = _CL_LOCAL_QUORUM, raise_on_error: bool = True):
        body = _pack_long_string(cql) + struct.pack(">HB", consistency, 0)
        op, payload = self.request(_OP_QUERY, body, raise_on_error=raise_on_error)
        if op == _OP_ERROR:
            return payload                              # a _CqlError the caller asked to inspect
        assert op == _OP_RESULT, f"expected RESULT (0x08), got opcode 0x{op:02X}"
        r = _Reader(payload)
        kind = r.int()
        if kind == 1:
            return []                                   # Void
        assert kind == 2, f"unexpected RESULT kind {kind!r}"
        flags = r.int()
        count = r.int()
        if flags & 0x0001:                              # Global_tables_spec
            r.string()
            r.string()
        cols = []
        for _ in range(count):
            if not flags & 0x0001:
                r.string()
                r.string()
            name = r.string()
            type_id = r.short()
            cols.append((name, _TYPE_NAMES.get(type_id, f"unknown-0x{type_id:04X}")))
        return [
            {cols[c][0]: _decode(cols[c][1], r.bytes_()) for c in range(len(cols))}
            for _ in range(r.int())
        ]

# ===== end inlined CQL client =====


def _kname(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix + "-").replace("-", "_")[:48]


def _while_in_use(fn, timeout_s: float = 600.0):
    """Teardown: retry a delete while a table under the keyspace is still being deleted."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_keyspace_ready(kc, ks_name: str, timeout_s: float = 180.0) -> None:
    """`list_tables` on a not-yet-visible keyspace does not reliably raise
    ResourceNotFoundException, so it under-reports readiness: measured, CreateTable issued right
    after a `list_tables`-based wait still answered `ResourceNotFoundException: Keyspace ... does
    not exist`. `get_keyspace` is the signal CreateTable itself waits on."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.get_keyspace(keyspaceName=ks_name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)


def _wait_table_status(kc, ks_name: str, tbl_name: str, target: str, timeout_s: float = 180.0) -> None:
    """GetTable answers ResourceNotFoundException ("unconfigured table") for a few seconds right
    after CreateTable returns -- tolerate that the same way CreateTable's own async propagation
    is tolerated, rather than letting it surface as an unrelated crash."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = kc.get_table(keyspaceName=ks_name, tableName=tbl_name)["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(3.0)
            continue
        if status == target:
            return
        time.sleep(3.0)
    raise AssertionError(f"table never reached {target}, last status {status}")


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

    Registered BEFORE the create so a failure in between cannot leak a principal.
    """
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-lwtcql-")[:64]
    ctx.on_cleanup(lambda: _delete_cql_user_quietly(iam, user))
    iam.create_user(UserName=user, Tags=[{"Key": "sim2real", "Value": scenario}])
    iam.put_user_policy(
        UserName=user, PolicyName="sim2real-cassandra",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                       '"Action":["cassandra:Select","cassandra:Modify"],"Resource":["*"]}]}')
    cred = iam.create_service_specific_credential(
        UserName=user, ServiceName="cassandra.amazonaws.com")["ServiceSpecificCredential"]
    return user, cred["ServiceUserName"], cred["ServicePassword"]


def _connect(host: str, username: str, password: str, budget_s: float = 300.0, *,
             port: int = _CQL_PORT) -> _CqlConnection:
    """Open one authenticated connection, retrying ONLY on the credential-propagation refusal.

    IAM exposes no condition that says "this service-specific credential is now usable", so the
    bounded retry on error 0x0100 IS the wait.
    """
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
    raise AssertionError(f"no CQL connection to {host} authenticated within {budget_s}s (last {last!r})")


_SCENARIO = "native-cql-lwt-concurrency"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:native", "plane:data")
def run(ctx) -> None:
    """Concurrent `INSERT ... IF NOT EXISTS` (Cassandra LWT) on the same key: exactly one racer
    wins. Native CQL only -- there is no AWS-JSON request/response pair for a row write, so wire
    cannot express this."""
    kc = ctx.client("keyspaces")
    ks_name = _kname(ctx, "sim2real_behav_ks")
    tbl_name = _kname(ctx, "sim2real_behav_tbl")

    user, cql_user, cql_password = _cql_credential(ctx, _SCENARIO)

    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _while_in_use(lambda: kc.delete_keyspace(keyspaceName=ks_name))))
    kc.create_keyspace(keyspaceName=ks_name, tags=[{"key": "sim2real", "value": _SCENARIO}])
    _wait_keyspace_ready(kc, ks_name)

    schema = {
        "allColumns": [{"name": "pk", "type": "text"}, {"name": "winner", "type": "text"}],
        "partitionKeys": [{"name": "pk"}],
    }
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: kc.delete_table(keyspaceName=ks_name, tableName=tbl_name)))
    kc.create_table(keyspaceName=ks_name, tableName=tbl_name, schemaDefinition=schema,
                     tags=[{"key": "sim2real", "value": _SCENARIO}])
    _wait_table_status(kc, ks_name, tbl_name, "ACTIVE", timeout_s=180.0)

    host, port = ctx.service_host(f"cassandra.{ctx.region}.amazonaws.com", _CQL_PORT)

    def _open(_i: int) -> _CqlConnection:
        conn = _connect(host, cql_user, cql_password, port=port)
        ctx.on_cleanup(conn.close)
        return conn

    with ThreadPoolExecutor(max_workers=8) as pool:
        conns = list(pool.map(_open, range(8)))

    def _race(i: int) -> bool:
        rows = conns[i].query(
            f'INSERT INTO "{ks_name}"."{tbl_name}" (pk, winner) VALUES '
            f"('contested', 'racer-{i}') IF NOT EXISTS")
        return bool(rows and rows[0].get("[applied]"))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_race, range(8)))

    assert sum(results) == 1, f"exactly one LWT insert must win a race on the same key, got {sum(results)} of 8"

    rows = conns[0].query(f'SELECT winner FROM "{ks_name}"."{tbl_name}" WHERE pk=\'contested\'')
    assert len(rows) == 1, "exactly one row must exist for the contested key after the race"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
