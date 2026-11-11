"""dsql-occ-write-conflict-rejects-the-losing-commit."""

from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "dsql-occ-write-conflict-rejects-the-losing-commit"
GROUP = 'transactions'
SERVICES = ['dsql']

_TABLE = "sim2real_dsql_occ"
_SEED = "hello-dsql"
_ACTIVE_TIMEOUT_S = 600.0
_CONNECT_BUDGET_S = 240.0
#: Teardown budget: the cluster delete is confirmed gone within this window.
_DELETE_TIMEOUT_S = 900.0
#: The non-blocking bound. A PostgreSQL backend BLOCKS the second UPDATE until the first
#: transaction commits; DSQL returns it at once.
_NONBLOCKING_BOUND_S = 5.0


# ===== helpers =====
def _wait_active(dsql, identifier, *, timeout_s=_ACTIVE_TIMEOUT_S, interval_s=5.0):
    """Poll get_cluster to ACTIVE and return the payload."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = dsql.get_cluster(identifier=identifier)
        if last.get("status") == "ACTIVE":
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"DSQL cluster {identifier} never reached ACTIVE within {timeout_s}s; last status "
                f"{last.get('status')!r}"
            )
        time.sleep(interval_s)


def _cluster_gone(dsql, identifier):
    """True when get_cluster no longer reports a live cluster."""
    from botocore.exceptions import ClientError

    try:
        return dsql.get_cluster(identifier=identifier).get("status") == "DELETED"
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise


def _delete_cluster_and_wait(dsql, identifier, *, timeout_s=_DELETE_TIMEOUT_S, interval_s=10.0):
    """Delete the cluster and poll until the API says it is gone. Returns True when it is.

    Inline rather than only in ``ctx.on_cleanup`` so a delete that never completes fails the
    check and does not leave the cluster behind.
    """
    from botocore.exceptions import ClientError

    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        if _cluster_gone(dsql, identifier):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval_s)


def _connect_with_retry(ctx, address, token, *, budget_s=_CONNECT_BUDGET_S, interval_s=5.0,
                        autocommit=True):
    """Open a real PostgreSQL wire connection to DSQL at ``address`` (``ctx.endpoint_host``).
    Never a skip: a driver that is absent or an endpoint that never accepts a connection is an
    AssertionError, because 'provisioned but unconnectable' is exactly the fidelity defect this
    check exists to catch."""
    import psycopg

    endpoint, port = address
    deadline = time.monotonic() + budget_s
    last = None
    while True:
        try:
            conn = psycopg.connect(
                host=endpoint, port=port, dbname="postgres", user="admin", password=token,
                connect_timeout=15, **_tls(),
                cursor_factory=psycopg.ClientCursor,
            )
            conn.autocommit = autocommit
            return conn
        except Exception as exc:  # noqa: BLE001 — endpoint warm-up, retried to the deadline
            last = exc
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"could not open a PostgreSQL wire connection to DSQL at {endpoint}:{port} within "
                    f"{budget_s}s: {last!r}"
                ) from last
            time.sleep(interval_s)


def _tls() -> dict:
    """libpq TLS settings: the session is encrypted without verifying the server's identity."""
    return {"sslmode": "require"}


def _rows(conn, statement, args=None):
    """Execute one statement; return its rows ([] when it produces no result set)."""
    cur = conn.cursor()
    try:
        cur.execute(statement, args)
        if cur.description is None:
            return []
        return [tuple(r) for r in cur.fetchall()]
    finally:
        cur.close()


def _pgcode_of(conn, statement):
    """The SQLSTATE the engine raised for *statement*, as an exact string.

    Raises when the statement unexpectedly SUCCEEDS, rather than returning a falsy sentinel that
    would read as a code mismatch.
    """
    import psycopg

    try:
        _rows(conn, statement)
    except psycopg.Error as exc:
        conn.rollback()
        return exc.sqlstate
    raise AssertionError(
        f"the engine ACCEPTED a statement real Aurora DSQL refuses: {statement!r}"
    )


def _ssl_attribute(conn, name):
    """libpq's PQsslAttribute for *conn*, read from the libpq psycopg itself loaded.

    psycopg 3 exposes ssl_in_use on PGconn but PQsslAttribute on neither PGconn nor ConnectionInfo
    (psycopg2's conn.info.ssl_attribute has no psycopg 3 counterpart), so this asks the same libpq
    for the negotiated attributes rather than trusting a second TLS stack's view of the session.
    """
    import ctypes

    with open("/proc/self/maps") as maps:
        path = next((line.split()[-1] for line in maps if "/libpq" in line), None)
    if path is None:
        raise AssertionError(
            "psycopg reports no loaded libpq, so the negotiated TLS attributes cannot be read"
        )
    libpq = ctypes.CDLL(path)
    libpq.PQsslAttribute.restype = ctypes.c_char_p
    libpq.PQsslAttribute.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    raw = libpq.PQsslAttribute(conn.pgconn.pgconn_ptr, name.encode())
    return raw.decode() if raw is not None else None


def _table_present(conn, name):
    """1 when *name* exists in information_schema.tables, else 0. Read from the engine."""
    got = _rows(conn, "SELECT count(*) FROM information_schema.tables WHERE table_name = %s",
                (name,))
    return got[0][0]


def _close_all(*conns):
    for conn in conns:
        if conn is None:
            continue
        try:
            conn.close()
        except Exception:  # noqa: BLE001 — best-effort session teardown
            pass
# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:negative-classes", "dp:native", "plane:data")
def run(ctx) -> None:
    """Of two DSQL transactions writing one row, exactly one commit is refused SQLSTATE 40001 and the
    conflicting UPDATE never blocks (optimistic concurrency, unlike PostgreSQL); DSQL also reports
    'repeatable read' as its default isolation and refuses SERIAL (42704) and TEMP tables (0A000)."""
    import psycopg

    dsql = ctx.client("dsql")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False,
        tags={"sim2real": "dsql-occ-write-conflict", "sim2real:managed": "true",
              "sim2real:prefix": "sim2real-behav"},
    )
    identifier = created["identifier"]
    # Failure-path net only; the verified teardown is inline in the finally below.
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(dsql, identifier, timeout_s=120.0))

    body_ok = False
    try:
        active = _wait_active(dsql, identifier)
        endpoint = active.get("endpoint")
        assert endpoint, f"an ACTIVE cluster must publish its endpoint in GetCluster; got {active!r}"
        token = dsql.generate_db_connect_admin_auth_token(
            Hostname=endpoint, Region=ctx.region, ExpiresIn=900)
        address = ctx.endpoint_host(endpoint, 5432)

        setup = _connect_with_retry(ctx, address, token)
        a = b = witness = None
        try:
            # --- 1. it really is the PostgreSQL wire protocol, over real TLS ---
            version = _rows(setup, "SELECT version()")
            assert version and version[0][0].startswith("PostgreSQL "), (
                f"DSQL must answer the PostgreSQL wire protocol and report a PostgreSQL server "
                f"version; SELECT version() returned {version!r}"
            )
            assert setup.pgconn.ssl_in_use is True, (
                "the DSQL session must be TLS; libpq reports ssl_in_use "
                f"{setup.pgconn.ssl_in_use!r}"
            )
            key_bits = int(_ssl_attribute(setup, "key_bits") or 0)
            assert key_bits >= 128, (
                f"the negotiated TLS cipher must carry at least 128 bits; libpq reports "
                f"{key_bits!r} with cipher {_ssl_attribute(setup, 'cipher')!r}"
            )
            who = _rows(setup, "SELECT current_user")
            assert who == [("admin",)], (
                f"the generate_db_connect_admin_auth_token password must map to the admin role; "
                f"SELECT current_user returned {who!r}"
            )

            # --- 2. the isolation default is DSQL's, not PostgreSQL's ---
            default_iso = _rows(setup, "SELECT current_setting('default_transaction_isolation')")
            assert default_iso == [("repeatable read",)], (
                "Aurora DSQL's default_transaction_isolation is 'repeatable read'; an emulator "
                "serving dsql from a stock PostgreSQL reports 'read committed'. The engine "
                f"reports {default_iso!r}"
            )

            # --- 3. seed, and prove the round trip ---
            _rows(setup, f"CREATE TABLE {_TABLE} (id INT PRIMARY KEY, payload TEXT)")
            _rows(setup, f"INSERT INTO {_TABLE} (id, payload) VALUES (1, %s)", (_SEED,))
            seeded = _rows(setup, f"SELECT id, payload FROM {_TABLE} WHERE id = 1")
            assert seeded == [(1, _SEED)], (
                f"the seeded row must round-trip over the wire as a full tuple; got {seeded!r}"
            )

            # --- 4. OCC: the losing commit is refused, and nothing ever blocked ---
            a = _connect_with_retry(ctx, address, token, budget_s=120.0, autocommit=False)
            b = _connect_with_retry(ctx, address, token, budget_s=120.0, autocommit=False)
            _rows(a, f"UPDATE {_TABLE} SET payload = 'from-a' WHERE id = 1")

            # A's write is uncommitted RIGHT NOW -- proven from a third session, so the
            # non-blocking bound below cannot be satisfied by A having already committed.
            witness = _connect_with_retry(ctx, address, token, budget_s=120.0)
            during = _rows(witness, f"SELECT payload FROM {_TABLE} WHERE id = 1")
            assert during == [(_SEED,)], (
                "session A's UPDATE must still be uncommitted and invisible to a third session "
                f"before session B writes the same row; the witness already reads {during!r}, so "
                "the non-blocking assertion below would be vacuous"
            )

            started = time.monotonic()
            _rows(b, f"UPDATE {_TABLE} SET payload = 'from-b' WHERE id = 1")
            elapsed = time.monotonic() - started
            # elapsed-bound: optimistic concurrency means B's UPDATE never waits on A's row lock
            assert elapsed < _NONBLOCKING_BOUND_S, (
                "Aurora DSQL detects write-write conflicts OPTIMISTICALLY at commit, so session "
                f"B's UPDATE of a row session A holds uncommitted must return immediately; it "
                f"took {elapsed:.2f}s, which is the lock-wait a stock PostgreSQL backend would "
                f"impose (bound {_NONBLOCKING_BOUND_S}s)"
            )

            refusals = []
            for name, conn in (("a", a), ("b", b)):
                try:
                    conn.commit()
                except psycopg.Error as exc:
                    refusals.append((name, exc))
            assert len(refusals) == 1, (
                "exactly one of the two conflicting transactions must be refused at commit; "
                f"{len(refusals)} were refused "
                f"({[(n, e.sqlstate) for n, e in refusals]!r})"
            )
            victim_name, victim_exc = refusals[0]
            assert victim_exc.sqlstate == "40001", (
                "the losing transaction must be refused with SQLSTATE 40001 "
                f"(serialization_failure); the engine raised {victim_exc.sqlstate!r}: "
                f"{str(victim_exc)[:200]!r}"
            )
            assert victim_exc.diag.sqlstate == "40001", (
                "the ErrorResponse diagnostic record must carry the same SQLSTATE as the exception "
                f"(it is a wire field, not a client-side invention); diag reports "
                f"{victim_exc.diag.sqlstate!r}"
            )
            assert victim_exc.diag.severity == "ERROR", (
                f"the refusal must arrive at severity ERROR; diag reports "
                f"{victim_exc.diag.severity!r}"
            )

            # Effect-absent: the loser's write left nothing behind, read from a third session.
            survivor_value = "from-b" if victim_name == "a" else "from-a"
            after = _rows(witness, f"SELECT payload FROM {_TABLE} WHERE id = 1")
            assert after == [(survivor_value,)], (
                f"only the surviving transaction's write may be present; session {victim_name!r} "
                f"was refused with 40001 yet an independent session reads {after!r} instead of "
                f"[({survivor_value!r},)]"
            )
            count = _rows(witness, f"SELECT count(*) FROM {_TABLE}")
            assert count == [(1,)], (
                f"the refused transaction must not have added a row; count(*) is {count!r}"
            )

            # --- 5. control: the 40001 was a conflict verdict, not a broken statement ---
            victim_conn = a if victim_name == "a" else b
            victim_conn.rollback()
            _rows(victim_conn, f"UPDATE {_TABLE} SET payload = 'retry-ok' WHERE id = 1")
            victim_conn.commit()
            retried = _rows(witness, f"SELECT payload FROM {_TABLE} WHERE id = 1")
            assert retried == [("retry-ok",)], (
                "re-running the refused transaction serially must now succeed, proving the 40001 "
                f"was a conflict verdict rather than a permanently broken statement; an "
                f"independent session reads {retried!r}"
            )

            # --- 6. DSQL refuses PostgreSQL features a stock PostgreSQL accepts ---
            serial_code = _pgcode_of(setup, "CREATE TABLE sim2real_dsql_serial (id SERIAL PRIMARY KEY)")
            assert serial_code == "42704", (
                "Aurora DSQL has no sequences, so SERIAL must be refused with SQLSTATE 42704 "
                f"(undefined_object); the engine raised {serial_code!r}"
            )
            assert _table_present(setup, "sim2real_dsql_serial") == 0, (
                "the refused SERIAL table must be absent from information_schema.tables"
            )

            temp_code = _pgcode_of(setup, "CREATE TEMP TABLE sim2real_dsql_tmp (x INT)")
            assert temp_code == "0A000", (
                "Aurora DSQL does not support TEMPORARY tables, so CREATE TEMP TABLE must be "
                f"refused with SQLSTATE 0A000 (feature_not_supported); the engine raised "
                f"{temp_code!r}"
            )
            assert _table_present(setup, "sim2real_dsql_tmp") == 0, (
                "the refused TEMP table must be absent from information_schema.tables"
            )

            # Positive control in the same session: DDL itself works.
            _rows(setup, "CREATE TABLE sim2real_dsql_ok (id INT PRIMARY KEY, v TEXT)")
            assert _table_present(setup, "sim2real_dsql_ok") == 1, (
                "an ordinary CREATE TABLE must succeed and appear in information_schema.tables, "
                "so the two refusals above are about the features and not about DDL being broken"
            )
        finally:
            _close_all(witness, b, a, setup)
        body_ok = True
    finally:
        gone = _delete_cluster_and_wait(dsql, identifier)
        if body_ok:
            assert gone is True, (
                f"the DSQL cluster {identifier} was not confirmed deleted within "
                f"{_DELETE_TIMEOUT_S}s -- reported as a leftover rather than left unverified"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
