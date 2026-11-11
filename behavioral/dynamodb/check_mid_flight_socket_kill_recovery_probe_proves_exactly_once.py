"""mid-flight-socket-kill-recovery-probe-proves-exactly-once."""

from __future__ import annotations

import socket
import struct
import uuid
from urllib.parse import urlsplit

from botocore.config import Config
from botocore.exceptions import ClientError, ConnectionClosedError
from behavioral_harness import tags

CHECK = "mid-flight-socket-kill-recovery-probe-proves-exactly-once"
GROUP = "idempotency-retry"
SERVICES = ["dynamodb"]
# botocore's max_attempts counts RETRIES, so this is 3 deliveries, all of them destroyed.
_MAX_ATTEMPTS = 2
_TOTAL_ATTEMPTS = _MAX_ATTEMPTS + 1
# Upper bound on the wait for the server's first response byte, which shows it processed the
# delivery; the socket is destroyed right after that byte, before the SDK reads a response.
_SETTLE_S = 15.0


def _header(request, name: str) -> str:
    """One request header as ``str``. botocore stamps ``amz-sdk-request`` as BYTES."""
    value = request.headers.get(name)
    if value is None:
        return ""
    return value.decode() if isinstance(value, bytes) else str(value)


def _kill_after_send(log: list):
    """A ``before-send`` handler that transmits the request, waits for the first byte of the
    HTTP response, and then RSTs the socket.

    The SDK never reads a response; ConnectionClosedError feeds botocore's retry policy.
    """
    import http.client
    import ssl

    def handler(request, **kwargs):
        u = urlsplit(request.url)
        port = u.port or (443 if u.scheme == "https" else 80)
        if u.scheme == "https":
            conn = http.client.HTTPSConnection(
                u.hostname, port, timeout=30, context=ssl.create_default_context()
            )
        else:
            conn = http.client.HTTPConnection(u.hostname, port, timeout=30)
        conn.connect()
        sock = conn.sock
        body = request.body or b""
        if isinstance(body, str):
            body = body.encode()
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        # SigV4 signs Host, so the signed header is forwarded rather than regenerated.
        conn.putrequest(request.method, path, skip_host=True, skip_accept_encoding=True)
        for k, v in request.headers.items():
            if k.lower() != "content-length":
                conn.putheader(k, v)
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        sock.sendall(body)
        # The first response byte means the server finished the delivery. It is read through TLS,
        # so a post-handshake session ticket, which makes the raw socket readable, does not count.
        sock.settimeout(_SETTLE_S)
        try:
            first = sock.recv(1)
        except TimeoutError as exc:
            raise TimeoutError(
                f"no response byte within {_SETTLE_S} s of a delivery; the outcome is unknown"
            ) from exc
        finally:
            # SO_LINGER {1, 0} makes close() a hard RST: the peer sees an abort, not a shutdown.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            sock.close()
        if not first:
            raise ConnectionError("the peer closed before a response byte; the outcome is unknown")
        log.append(_header(request, "amz-sdk-request"))
        raise ConnectionClosedError(endpoint_url=request.url)

    return handler


def _delete_table_if_present(client, table: str) -> None:
    """Teardown for a table the check itself deletes on its success path."""
    try:
        client.delete_table(TableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With every delivery destroyed mid-flight, a token'd TransactWriteItems ADD commits once, a
    same-token replay stays at 1 and a fresh token moves it to 2, while the token-less UpdateItem
    control commits once per delivery; outcomes are read back with consistent GetItem.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    plain = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-d3kill-")
    plain.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_if_present(plain, table))
    plain.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    killer = ctx.client(
        "dynamodb",
        config=Config(retries={"max_attempts": _MAX_ATTEMPTS, "mode": "standard"}),
    )
    total = killer.meta.config.retries["total_max_attempts"]
    assert total == _TOTAL_ATTEMPTS, (
        f"max_attempts={_MAX_ATTEMPTS} normalized to total_max_attempts={total!r}; max_attempts "
        f"counts RETRIES, so the ceiling must be {_TOTAL_ATTEMPTS}"
    )

    def counter(key):
        item = plain.get_item(
            TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True
        ).get("Item")
        return None if item is None else item["n"]["N"]

    def increment(key):
        return {
            "TableName": table,
            "Key": {"pk": {"S": key}},
            "UpdateExpression": "ADD n :one",
            "ExpressionAttributeValues": {":one": {"N": "1"}},
        }

    # --- arm A: token'd, every delivery destroyed mid-flight ---
    token = str(uuid.uuid4())
    log = []
    handler = _kill_after_send(log)
    killer.meta.events.register("before-send.dynamodb.TransactWriteItems", handler)
    try:
        killer.transact_write_items(
            ClientRequestToken=token, TransactItems=[{"Update": increment("tokened")}]
        )
        raise AssertionError(
            "transact_write_items returned a result although every socket was destroyed before a "
            "response byte could be read"
        )
    except ConnectionClosedError:
        pass
    finally:
        killer.meta.events.unregister(
            "before-send.dynamodb.TransactWriteItems", handler
        )

    assert len(log) == total, (
        f"the token'd request was transmitted {len(log)} times, expected {total}; the SDK must "
        f"retry a connection lost mid-flight up to its ceiling"
    )
    assert "max=" not in log[0] and "attempt=1" in log[0], (
        f"first delivery stamped amz-sdk-request={log[0]!r}; attempt 1 carries attempt=1, no max="
    )
    for i, stamp in enumerate(log[1:], start=2):
        assert f"attempt={i}; max={total}" in stamp, (
            f'delivery {i} stamped amz-sdk-request={stamp!r}, expected "attempt={i}; max={total}"'
        )

    # the recovery probe: the ONLY way this outcome is readable
    assert counter("tokened") == "1", (
        f"after {total} destroyed deliveries of one ClientRequestToken the counter reads "
        f"{counter('tokened')!r}, expected '1' — a ledger consulted at commit time is what makes "
        f"this exactly-once, and a response cache cannot supply it because no response was read"
    )

    # Parameters must be identical: even ReturnConsumedCapacity is part of the idempotency
    # fingerprint and would raise IdempotentParameterMismatchException.
    killer.transact_write_items(
        ClientRequestToken=token, TransactItems=[{"Update": increment("tokened")}]
    )
    assert counter("tokened") == "1", (
        f"a clean replay of the same token moved the counter to {counter('tokened')!r}; the "
        f"killed deliveries had already established the ledger entry"
    )

    # positive control: a fresh token applies the work a second time, so the table is writable
    killer.transact_write_items(
        ClientRequestToken=str(uuid.uuid4()),
        TransactItems=[{"Update": increment("tokened")}],
    )
    assert counter("tokened") == "2", (
        f"a FRESH token left the counter at {counter('tokened')!r}, expected '2' — dedup must be "
        f"scoped to the token, not to the request shape"
    )

    # --- arm B (control): token-LESS, every delivery destroyed the same way ---
    log_b = []
    handler_b = _kill_after_send(log_b)
    killer.meta.events.register("before-send.dynamodb.UpdateItem", handler_b)
    try:
        killer.update_item(**increment("tokenless"))
        raise AssertionError(
            "update_item returned a result although every socket was destroyed before a response "
            "byte could be read"
        )
    except ConnectionClosedError:
        pass
    finally:
        killer.meta.events.unregister("before-send.dynamodb.UpdateItem", handler_b)

    assert len(log_b) == total, (
        f"the token-less request was transmitted {len(log_b)} times, expected {total}"
    )
    assert counter("tokenless") == str(total), (
        f"the token-less counter reads {counter('tokenless')!r} after {total} destroyed "
        f"deliveries, expected {str(total)!r}; if this is not {total} the kill did not actually "
        f"deliver every attempt and arm A's '1' proves nothing about the service"
    )

    # --- cleanup verification ---
    plain.delete_table(TableName=table)
    plain.get_waiter("table_not_exists").wait(
        TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 100}
    )
    try:
        plain.describe_table(TableName=table)
        raise AssertionError(f"{table} still describable after delete_table")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", (
            f"describe_table on the deleted table raised {code!r}, expected "
            f"ResourceNotFoundException"
        )
        expected = f"Requested resource not found: Table: {table} not found"
        assert message == expected, (
            f"describe_table on the deleted table answered {message!r}, expected {expected!r}"
        )

    try:
        plain.update_item(**increment("tokened"))
        raise AssertionError("update_item succeeded against a table already deleted")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", (
            f"update_item on the deleted table raised {code!r}, expected "
            f"ResourceNotFoundException"
        )
        assert message == "Requested resource not found", (
            f"update_item on the deleted table answered {message!r}, expected "
            f"'Requested resource not found'"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
