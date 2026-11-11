"""sdk-retry-replays-the-wire-and-only-the-token-stops-the-duplicate."""
from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from botocore.awsrequest import AWSResponse
from botocore.config import Config
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "sdk-retry-replays-the-wire-and-only-the-token-stops-the-duplicate"
GROUP = 'idempotency-retry'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'
_INJECTED_MESSAGE = 'injected by a before-send hook'

# botocore's `max_attempts` counts RETRIES, so the normalized ceiling is N+1 deliveries.
_MODES_AND_ATTEMPTS = (
    ('standard', 1), ('standard', 3), ('adaptive', 1), ('adaptive', 3),
    ('legacy', 1), ('legacy', 3),
)
# The pairs whose effect count is measured: every mode and both attempt counts are covered, while
# exponential backoff (rand() * min(2**(n-1), 20) s per retry) keeps the run time bounded.
_EFFECT_ARMS = (('standard', 1), ('standard', 3), ('adaptive', 3), ('legacy', 3))


class _ReplayableBody:
    """A minimal urllib3-shaped body for a fabricated ``AWSResponse``.

    ``AWSResponse.content`` calls ``raw.stream()``, which a bare ``io.BytesIO`` lacks.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def stream(self, amt=None, **kwargs):
        if self._pos < len(self._data):
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
            yield chunk

    def read(self, amt=None):
        chunk = self._data[self._pos:] if amt is None else self._data[self._pos:self._pos + amt]
        self._pos += len(chunk)
        return chunk

    def close(self):
        return None


def _transmit(request):
    """Send a signed ``AWSPreparedRequest`` by hand; return ``(status, lowercased_headers)``.

    Exactly one ``Host`` header is sent: the front end answers a Host-less or two-Host request 400.
    """
    import http.client
    import ssl

    u = urlsplit(request.url)
    port = u.port or (443 if u.scheme == 'https' else 80)
    if u.scheme == 'https':
        conn = http.client.HTTPSConnection(
            u.hostname, port, timeout=30, context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(u.hostname, port, timeout=30)
    conn.connect()
    try:
        body = request.body or b''
        if isinstance(body, str):
            body = body.encode()
        path = (u.path or '/') + (('?' + u.query) if u.query else '')
        conn.putrequest(request.method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader('Host', _header(request, 'host') or u.hostname)
        for k, v in request.headers.items():
            if k.lower() not in ('content-length', 'host'):
                conn.putheader(k, v)
        conn.putheader('Content-Length', str(len(body)))
        conn.endheaders()
        conn.sock.sendall(body)
        resp = conn.getresponse()
        resp.read()
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}
    finally:
        conn.close()


def _teardown(undo, *not_found):
    """A cleanup running ``undo()`` that returns only on the resource's own not-found codes."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response['Error']['Code'] in not_found:
                return
            raise

    return run_undo


def _header(request, name: str) -> str:
    """One request header as ``str``. botocore stamps ``amz-sdk-request`` as BYTES."""
    value = request.headers.get(name)
    if value is None:
        return ''
    return value.decode() if isinstance(value, bytes) else str(value)


def _forward_then_lie(status: int, err_type: str, log: list):
    """A ``before-send`` handler that really executes the request and then reports ``status``.

    Logs ``(real_status, x-amzn-RequestId, amz-sdk-request, amz-sdk-invocation-id)`` per call.
    """
    payload = ('{"__type":"aws#%s","message":"%s"}' % (err_type, _INJECTED_MESSAGE)).encode()

    def handler(request, **kwargs):
        real_status, headers = _transmit(request)
        log.append((real_status, headers.get('x-amzn-requestid'),
                    _header(request, 'amz-sdk-request'),
                    _header(request, 'amz-sdk-invocation-id')))
        return AWSResponse(
            request.url, status,
            {'Content-Type': 'application/x-amz-json-1.0', 'Content-Length': str(len(payload))},
            _ReplayableBody(payload),
        )

    return handler


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A 503 faked after each real commit makes a token-less UpdateItem ADD land total_max_attempts
    times, while a TransactWriteItems with ClientRequestToken lands once, in every retry mode.
    A real ValidationException is delivered once and writes nothing.
    """
    plain = ctx.client('dynamodb')
    table = ctx.unique_name('sim2real-behav-d3retry-')
    plain.create_table(
        TableName=table,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: plain.delete_table(TableName=table),
                             'ResourceNotFoundException'))
    plain.get_waiter('table_exists').wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    def counter(key):
        item = plain.get_item(
            TableName=table, Key={'pk': {'S': key}}, ConsistentRead=True).get('Item')
        return None if item is None else item['n']['N']

    def increment(key):
        return {'TableName': table, 'Key': {'pk': {'S': key}},
                'UpdateExpression': 'ADD n :one',
                'ExpressionAttributeValues': {':one': {'N': '1'}}}

    totals = {}
    for mode, attempts in _MODES_AND_ATTEMPTS:
        client = ctx.client(
            'dynamodb', config=Config(retries={'max_attempts': attempts, 'mode': mode}))
        got = client.meta.config.retries['total_max_attempts']
        assert got == attempts + 1, (
            f'{mode} mode with max_attempts={attempts} normalized to total_max_attempts={got!r}; '
            f'max_attempts counts RETRIES, so the ceiling must be {attempts + 1}'
        )
        totals[(mode, attempts)] = got

    for mode, attempts in _EFFECT_ARMS:
        total = totals[(mode, attempts)]
        client = ctx.client(
            'dynamodb', config=Config(retries={'max_attempts': attempts, 'mode': mode}))
        key = f'notoken-{mode}-{attempts}'
        log = []
        handler = _forward_then_lie(503, 'ServiceUnavailableException', log)
        client.meta.events.register('before-send.dynamodb.UpdateItem', handler)
        try:
            client.update_item(**increment(key))
            raise AssertionError(
                f'{mode}/{attempts}: the injected 503 was reported as success — the fabricated '
                f'AWSResponse never reached the parser'
            )
        except ClientError as exc:
            code = exc.response['Error']['Code']
            assert code == 'ServiceUnavailableException', (
                f'{mode}/{attempts}: injected 503 surfaced as {code!r}, not the error the '
                f'fabricated body declares'
            )
            message = exc.response['Error'].get('Message')
            assert message == _INJECTED_MESSAGE, (
                f'{mode}/{attempts}: injected 503 surfaced the message {message!r}, not the '
                f'{_INJECTED_MESSAGE!r} the fabricated body declares'
            )
        finally:
            client.meta.events.unregister('before-send.dynamodb.UpdateItem', handler)

        assert len(log) == total, (
            f'{mode}/{attempts}: the request went on the wire {len(log)} times, expected '
            f'{total} (max_attempts={attempts} means {attempts} RETRIES)'
        )
        assert all(entry[0] == 200 for entry in log), (
            f'{mode}/{attempts}: real service statuses were {[e[0] for e in log]!r}; every '
            f'forwarded attempt must have COMMITTED before the 503 was fabricated'
        )
        assert counter(key) == str(total), (
            f'{mode}/{attempts}: token-less counter reads {counter(key)!r} after {total} '
            f'deliveries, expected {str(total)!r} — the SDK duplicated the effect and nothing '
            f'deduplicated it'
        )
        invocation_ids = {entry[3] for entry in log}
        assert len(invocation_ids) == 1 and '' not in invocation_ids, (
            f'{mode}/{attempts}: amz-sdk-invocation-id was {sorted(invocation_ids)!r}; it must be '
            f'one stable value across every attempt of one logical call'
        )
        request_ids = {entry[1] for entry in log}
        assert len(request_ids) == total and None not in request_ids, (
            f'{mode}/{attempts}: the service returned {len(request_ids)} distinct '
            f'x-amzn-RequestId values across {total} deliveries ({sorted(request_ids)!r}); each '
            f'attempt is a separate request and must be answered as one'
        )
        sdk_request = [entry[2] for entry in log]
        assert 'max=' not in sdk_request[0] and 'attempt=1' in sdk_request[0], (
            f'{mode}/{attempts}: first attempt stamped amz-sdk-request={sdk_request[0]!r}; '
            f'attempt 1 carries attempt=1 and no max='
        )
        for i, stamp in enumerate(sdk_request[1:], start=2):
            assert f'attempt={i}; max={total}' in stamp, (
                f'{mode}/{attempts}: attempt {i} stamped amz-sdk-request={stamp!r}, expected '
                f'"attempt={i}; max={total}"'
            )

    for mode, attempts in _EFFECT_ARMS:
        total = totals[(mode, attempts)]
        client = ctx.client(
            'dynamodb', config=Config(retries={'max_attempts': attempts, 'mode': mode}))
        key = f'token-{mode}-{attempts}'
        log = []
        handler = _forward_then_lie(503, 'ServiceUnavailableException', log)
        client.meta.events.register('before-send.dynamodb.TransactWriteItems', handler)
        try:
            client.transact_write_items(
                ClientRequestToken=str(uuid.uuid4()),
                TransactItems=[{'Update': increment(key)}])
            raise AssertionError(
                f'{mode}/{attempts}: the injected 503 was reported as success on the token\'d arm')
        except ClientError as exc:
            code = exc.response['Error']['Code']
            assert code == 'ServiceUnavailableException', (
                f'{mode}/{attempts}: token\'d arm surfaced {code!r}, not the injected error')
            message = exc.response['Error'].get('Message')
            assert message == _INJECTED_MESSAGE, (
                f'{mode}/{attempts}: token\'d arm surfaced the message {message!r}, not the '
                f'injected {_INJECTED_MESSAGE!r}')
        finally:
            client.meta.events.unregister('before-send.dynamodb.TransactWriteItems', handler)

        assert len(log) == total, (
            f'{mode}/{attempts}: token\'d request went on the wire {len(log)} times, expected '
            f'{total} — the token must not change how often the SDK retries'
        )
        assert counter(key) == '1', (
            f'{mode}/{attempts}: token\'d counter reads {counter(key)!r} after {total} '
            f'deliveries of one ClientRequestToken, expected \'1\''
        )

    # Adaptive and standard differ in rate, not in delivery count.
    assert totals[('adaptive', 3)] == totals[('standard', 3)] == 4, (
        f'adaptive normalized to {totals[("adaptive", 3)]!r} and standard to '
        f'{totals[("standard", 3)]!r} for max_attempts=3; both must be 4'
    )
    assert counter('notoken-adaptive-3') == counter('notoken-standard-3') == '4', (
        f'adaptive delivered {counter("notoken-adaptive-3")!r} effects and standard '
        f'{counter("notoken-standard-3")!r}; the two modes throttle differently but retry the '
        f'same number of times'
    )

    client = ctx.client('dynamodb', config=Config(retries={'max_attempts': 3, 'mode': 'standard'}))
    deliveries = []

    def record(request, **kwargs):
        deliveries.append(request.url)

    client.meta.events.register('before-send.dynamodb.UpdateItem', record)
    try:
        client.update_item(
            TableName=table, Key={'pk': {'S': 'rejected'}}, UpdateExpression='ADD n :one',
            ExpressionAttributeValues={':one': {'S': 'not-a-number'}})
        raise AssertionError(
            'ADD with a string operand was accepted; real AWS rejects it with ValidationException')
    except ClientError as exc:
        code = exc.response['Error']['Code']
        assert code == ERR_VALIDATION, (
            f'ADD with a string operand raised {code!r}, expected {ERR_VALIDATION!r}')
        message = exc.response['Error'].get('Message')
        add_message = ('1 validation error detected: Invalid UpdateExpression: Incorrect operand '
                       'type for operator or function; operator: ADD, operand type: STRING, '
                       'typeSet: ALLOWED_FOR_ADD_OPERAND')
        assert message == add_message, (
            f'ADD with a string operand raised the message {message!r}, expected {add_message!r}')
        status = exc.response['ResponseMetadata']['HTTPStatusCode']
        assert status == 400, f'ValidationException came back with HTTP {status!r}, expected 400'
    finally:
        client.meta.events.unregister('before-send.dynamodb.UpdateItem', record)

    assert len(deliveries) == 1, (
        f'a 400 ValidationException was put on the wire {len(deliveries)} times on a client whose '
        f'total_max_attempts is {client.meta.config.retries["total_max_attempts"]!r}; a domain '
        f'error must not be retried — an emulator that answers 5xx here is retried and duplicates'
    )
    assert counter('rejected') is None, (
        f'the rejected ADD left an item behind: n={counter("rejected")!r}')

    plain.update_item(**increment('rejected'))
    assert counter('rejected') == '1', (
        f'positive control failed: a valid ADD on the same key left n={counter("rejected")!r}, '
        f'expected \'1\' — the table was writable all along'
    )

    plain.delete_table(TableName=table)
    waiter = plain.get_waiter('table_not_exists')
    waiter.wait(TableName=table, WaiterConfig={'Delay': 2, 'MaxAttempts': 100})
    try:
        plain.describe_table(TableName=table)
        raise AssertionError(f'{table} still describable after delete_table')
    except ClientError as exc:
        code = exc.response['Error']['Code']
        assert code == 'ResourceNotFoundException', (
            f'describe_table on the deleted table raised {code!r}, expected '
            f'ResourceNotFoundException')
        message = exc.response['Error'].get('Message')
        assert message == f'Requested resource not found: Table: {table} not found', (
            f'describe_table on the deleted table raised the message {message!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
