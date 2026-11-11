"""validation-messages-are-customer-intelligible."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "validation-messages-are-customer-intelligible"
GROUP = 'error-semantics'
SERVICES = ['dynamodb']
ERR_VALIDATION = 'ValidationException'

# Markers that only appear when an implementation detail has escaped into the
# response: a decoder's own diagnostic, a language-level type or panic, or a
# byte offset into the request. None of these is actionable by a caller, and a
# caller cannot tell from them WHICH input was wrong.
LEAK_MARKERS = (
    'union ',
    'Offset(',
    'offset:',
    'panicked',
    'unwrap',
    'Traceback',
    'serde',
    'Deserialize',
    'deserializ',
    'NoneType',
    'nullptr',
    '::',
    'ValueNull',
    'ValueNumber',
    'ValueString',
)


def _error(fn) -> tuple[str, str]:
    """The (code, message) pair *fn* raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get('Error', {})
        return err.get('Code'), err.get('Message') or ''
    raise AssertionError(f'real AWS rejects this call, but it SUCCEEDED and returned {result!r}')


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Seven malformed requests each fail with ValidationException and AWS's exact Message, which
    names the violated concept and has no LEAK_MARKERS: it is what tells a caller what to fix."""
    ddb = ctx.client('dynamodb')
    t = ctx.unique_name('sim2real-behav-')
    ddb.create_table(
        TableName=t,
        KeySchema=[{'AttributeName': 'pk', 'KeyType': 'HASH'}],
        AttributeDefinitions=[{'AttributeName': 'pk', 'AttributeType': 'S'}],
        BillingMode='PAY_PER_REQUEST',
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter('table_exists').wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # (label, call, domain terms any one of which must appear in the message, the exact message)
    cases = (
        ('malformed table name',
         lambda: ddb.get_item(TableName='ab', Key={'pk': {'S': 'k'}}),
         ('table', 'index', 'name'),
         "1 validation error detected: Value 'ab' at 'tableName' failed to satisfy constraint: "
         'Member must have length greater than or equal to 3'),
        ('number precision overflow',
         lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'n'}, 'n': {'N': '9' * 39}}),
         ('number', 'precision', 'digit', 'numeric'),
         '1 validation error detected: Attempting to store more than 38 significant digits in a '
         'Number'),
        ('empty string set',
         lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 's'}, 's': {'SS': []}}),
         ('set', 'empty', 'parameter'),
         '1 validation error detected: One or more parameter values were invalid: An string set  '
         'may not be empty'),
        ('duplicate set member',
         lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'd'}, 's': {'SS': ['a', 'a']}}),
         ('duplicate', 'set', 'collection'),
         '1 validation error detected: One or more parameter values were invalid: Input collection '
         '["a", "a"] contains duplicates.'),
        ('empty attribute value',
         lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'e'}, 'bad': {}}),
         ('attributevalue', 'attribute', 'datatype', 'empty'),
         'Supplied AttributeValue is empty, must contain exactly one of the supported datatypes'),
        ('invalid ReturnValues',
         lambda: ddb.put_item(TableName=t, Item={'pk': {'S': 'r'}}, ReturnValues='BOGUS'),
         ('return', 'value'),
         # AWS's verbatim text: no "Value ... at ..." prefix, and its enum list spells UPDATE_NEW.
         '1 validation error detected: Failed to satisfy constraint: Member must satisfy enum value '
         'set: [ALL_OLD, UPDATED_OLD, ALL_NEW, UPDATE_NEW, NONE]'),
        ('unparseable condition expression',
         lambda: ddb.put_item(
             TableName=t, Item={'pk': {'S': 'c'}}, ConditionExpression='attribute_exists('
         ),
         ('expression', 'syntax', 'token'),
         '1 validation error detected: Invalid ConditionExpression: Syntax error; token: "<EOF>", '
         'near: "("'),
        ('invalid BatchGetItem ReturnConsumedCapacity enum',
         lambda: ddb.batch_get_item(
             RequestItems={t: {'Keys': [{'pk': {'S': 'g'}}]}}, ReturnConsumedCapacity='BOGUS'
         ),
         ('returnconsumedcapacity', 'enum', 'value'),
         "1 validation error detected: Value 'BOGUS' at 'returnConsumedCapacity' failed to "
         'satisfy constraint: Member must satisfy enum value set: [INDEXES, TOTAL, NONE]'),
        ('empty map-attribute key in BatchWriteItem',
         lambda: ddb.batch_write_item(
             RequestItems={t: [{'PutRequest': {'Item': {'pk': {'S': 'm'}, 'nested': {'M': {'': {'S': 'v'}}}}}}]}
         ),
         ('attribute', 'name', 'empty'),
         'Empty attribute name'),
    )

    for label, call, terms, expected_message in cases:
        code, message = _error(call)
        assert code == ERR_VALIDATION, f'{label}: expected {ERR_VALIDATION}, got {code!r}'
        assert message == expected_message, (
            f'{label}: expected the message {expected_message!r}, got {message!r}'
        )
        assert message.strip(), f'{label}: {ERR_VALIDATION} must carry a non-empty Message'
        low = message.lower()
        assert any(term in low for term in terms), (
            f'{label}: Message must name the subject (one of {terms}), got {message!r}'
        )
        leaked = [m for m in LEAK_MARKERS if m.lower() in low]
        assert not leaked, (
            f'{label}: Message leaks implementation detail {leaked} and is not actionable '
            f'by a caller: {message!r}'
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
