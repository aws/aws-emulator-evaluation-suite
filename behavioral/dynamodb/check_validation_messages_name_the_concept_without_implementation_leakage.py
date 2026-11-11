"""validation-messages-name-the-concept-without-implementation-leakage."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validation-messages-name-the-concept-without-implementation-leakage"
GROUP = 'errors'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

#: Substrings that betray the implementation behind the endpoint rather than describing the
#: customer's mistake: decoder diagnostics, byte offsets, language type and namespace markers, and
#: crash residue.
_LEAKAGE = (
    '::', 'panic', 'unwrap', 'serde', 'traceback', 'stack backtrace', 'goroutine',
    'nullpointerexception', 'java.lang', 'sun.reflect', 'site-packages', '.rs:', '.py:', '.java:',
    'byte offset', 'at offset', 'expected value at line', 'option<', 'result<', 'struct ',
    'no such field', 'cannot deserialize', 'deserialization', 'unmarshal', 'typeerror',
)

#: A file-and-line or stack-frame shape, which no customer-facing message should ever carry.
_FRAME = re.compile(r'\b\w+\.(rs|py|java|go|kt|cpp)\b|\bline \d+\b|\bcolumn \d+\b', re.I)


def _message(fn, what: str, expected: str) -> str:
    """The Message of a refused call, asserted to be ``expected``; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        assert err.get('Code') == ERR_VALIDATION, (
            f'{what}: expected {ERR_VALIDATION} so the message below is the validation surface, got '
            f'{err.get("Code")!r}'
        )
        assert err.get('Message') == expected, (
            f'{what}: expected the message {expected!r}, got {err.get("Message")!r}'
        )
        return err.get('Message') or ''
    raise AssertionError(f'{what}: the call was ACCEPTED; real AWS rejects it')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Each of eight ValidationException messages names the violated concept (parameter, type, limit)
    and contains no implementation leakage such as decoder diagnostics, offsets or stack-frame shapes;
    refused writes store nothing.
    """
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-msg-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: the same operations on the same table succeed, so the messages below come
    # from the validation surface and not from a target that refuses everything.
    ddb.put_item(TableName=t, Item={'pk': {'S': 'ctl'}, 'n': {'N': '1'}})
    ctl = ddb.get_item(TableName=t, Key={'pk': {'S': 'ctl'}}, ConsistentRead=True,
                       ProjectionExpression='n', ReturnConsumedCapacity='TOTAL')
    assert ctl.get('Item') == {'n': {'N': '1'}}, (
        f'positive control: a well-formed PutItem/GetItem with a projection must work, got '
        f'{ctl.get("Item")!r}'
    )

    # Each case pairs a refusal with the concept its message must name. The keys are the pk values
    # the refused writes addressed, so the effect-absent sweep below can look for them.
    nested_over_limit = {'S': 'leaf'}
    for _ in range(32):
        nested_over_limit = {'M': {'n': nested_over_limit}}

    cases = {
        'a table name below the length floor': (
            lambda: ddb.get_item(TableName='ab', Key={'pk': {'S': 'x'}}),
            ('tablename', 'length'), None,
            "1 validation error detected: Value 'ab' at 'tableName' failed to satisfy constraint: "
            'Member must have length greater than or equal to 3'),
        'an unknown ReturnConsumedCapacity enum value': (
            lambda: ddb.get_item(TableName=t, Key={'pk': {'S': 'ctl'}},
                                 ReturnConsumedCapacity='NOPE'),
            ('returnconsumedcapacity', 'enum'), None,
            "1 validation error detected: Value 'NOPE' at 'returnConsumedCapacity' failed to satisfy "
            'constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]'),
        'an AttributeValue carrying no type member': (
            lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'msg-union'}, 'a': {}}),
            ('attributevalue', 'datatype'), 'msg-union',
            'Supplied AttributeValue is empty, must contain exactly one of the supported datatypes'),
        'a key that does not match the declared schema': (
            lambda: ddb.get_item(TableName=t, Key={'pk': {'N': '1'}}),
            ('key', 'schema'), None,
            'The provided key element does not match the schema'),
        'an empty string as a key attribute value': (
            lambda: ddb.put_item(TableName=t, Item={'pk': {'S': ''}}),
            ('empty string', 'pk'), None,
            'One or more parameter values are not valid. The AttributeValue for a key attribute cannot '
            'contain an empty string value. Key: pk'),
        'a projection expression that does not parse': (
            lambda: ddb.get_item(TableName=t, Key={'pk': {'S': 'ctl'}}, ProjectionExpression='1+'),
            ('projectionexpression', 'syntax error'), None,
            'Invalid ProjectionExpression: Syntax error; token: "1", near: "1+"'),
        'a document nested past the depth limit': (
            lambda: ddb.put_item(TableName=t,
                                 Item={'pk': {'S': 'msg-nest'}, 'd': nested_over_limit}),
            ('nesting', 'limit'), 'msg-nest',
            '1 validation error detected: Nesting Levels have exceeded supported limits: Attributes in '
            'the item have nested levels beyond supported limit'),
        'a number carrying more significant digits than are supported': (
            lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'msg-num'}, 'n': {'N': '9' * 39}}),
            ('38', 'significant digits'), 'msg-num',
            '1 validation error detected: Attempting to store more than 38 significant digits in a '
            'Number'),
    }

    for why, (call, required, _key, expected) in cases.items():
        message = _message(call, f'a request carrying {why}', expected)
        low = message.lower()
        assert len(message.strip()) >= 10, (
            f'the refusal for {why} must describe the mistake, but its Message was {message!r}'
        )
        assert len(message) <= 600, (
            f'the refusal for {why} returned a {len(message)}-character Message; a customer-facing '
            f'validation message is a sentence, not a dump: {message[:200]!r}'
        )
        for token in required:
            assert token in low, (
                f'the refusal for {why} must name the violated concept {token!r} in its Message, got '
                f'{message!r}'
            )
        for marker in _LEAKAGE:
            assert marker not in low, (
                f'the Message for {why} leaks the implementation behind the endpoint: it contains '
                f'{marker!r}. A customer-facing validation message describes the request, not the '
                f'parser. Got {message!r}'
            )
        frame = _FRAME.search(message)
        assert frame is None, (
            f'the Message for {why} carries a source-location shape {frame.group(0)!r}, which is '
            f'decoder diagnostics rather than a description of the request: {message!r}'
        )

    # --- effect absent: every refused write left nothing behind ---
    for why, (_call, _required, key, _expected) in cases.items():
        if key is None:
            continue
        got = ddb.get_item(TableName=t, Key={'pk': {'S': key}}, ConsistentRead=True)
        assert 'Item' not in got, (
            f'the write refused for {why} must leave nothing behind at pk={key!r}, got '
            f'{got.get("Item")!r}'
        )
    scanned = ddb.scan(TableName=t, ConsistentRead=True, Select='COUNT')
    assert scanned['Count'] == 1, (
        f'only the control item may exist after eight refused requests, got {scanned["Count"]!r}'
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
