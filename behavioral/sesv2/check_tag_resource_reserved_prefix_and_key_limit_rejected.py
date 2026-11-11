"""tag-resource-reserved-prefix-and-key-limit-rejected."""
from __future__ import annotations

CHECK = "tag-resource-reserved-prefix-and-key-limit-rejected"
GROUP = 'tagging-v2'
SERVICES = ['sesv2']

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError('expected the tagging call to be refused, but it succeeded')


def _tag_map(ses, arn):
    return {t['Key']: t['Value'] for t in ses.list_tags_for_resource(ResourceArn=arn)['Tags']}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource refuses the reserved `aws:` key prefix and an over-length key with distinct errors,
    applies no part of a batch containing a bad key, and leaves existing tags unchanged.
    """
    ses = ctx.client('sesv2')
    account = ctx.client('sts').get_caller_identity()['Account']

    name = ctx.unique_name('sim2real-behav-tagneg-')
    ses.create_configuration_set(ConfigurationSetName=name)
    ctx.on_cleanup(lambda _k=name: ses.delete_configuration_set(ConfigurationSetName=_k))
    arn = f"arn:aws:ses:{ctx.region}:{account}:configuration-set/{name}"

    ses.tag_resource(ResourceArn=arn, Tags=[{'Key': 'sim2real-owner', 'Value': 'parity'}])
    baseline = _tag_map(ses, arn)
    assert baseline.get('sim2real-owner') == 'parity', f"setup precondition: tag not stored, got {baseline!r}"

    err_reserved = _client_error(lambda: ses.tag_resource(
        ResourceArn=arn, Tags=[{'Key': 'aws:sim2real', 'Value': 'nope'}]))
    code_reserved = err_reserved.response['Error']['Code']
    msg_reserved = err_reserved.response['Error'].get('Message') or ''
    assert code_reserved == 'BadRequestException', (
        f"the reserved 'aws:' tag prefix must be refused with BadRequestException, got {code_reserved!r}: "
        f"{msg_reserved!r}"
    )
    assert msg_reserved == 'Failed to tag resource', (
        f"expected the reserved-prefix refusal message 'Failed to tag resource', got {msg_reserved!r}"
    )
    tags_now = _tag_map(ses, arn)
    assert 'aws:sim2real' not in tags_now, (
        f"a refused reserved-prefix tag must not be stored, tags are now {tags_now!r}"
    )

    # botocore does not validate `max`, so the over-length key reaches the server.
    long_key = 'k' * 129
    err_long = _client_error(lambda: ses.tag_resource(
        ResourceArn=arn, Tags=[{'Key': long_key, 'Value': 'nope'}]))
    code_long = err_long.response['Error']['Code']
    msg_long = err_long.response['Error'].get('Message') or ''
    # The length limit is a shape constraint (ValidationException, empty Message); the `aws:` prefix
    # is a tagging rule (BadRequestException).
    assert code_long == 'ValidationException', (
        f"a 129-character tag key exceeds the modeled TagKey maximum and must be refused with "
        f"ValidationException, got {code_long!r}: {msg_long!r}"
    )
    assert msg_long == '', f"AWS answers the over-length key with an empty Message, got {msg_long!r}"
    assert code_long != code_reserved, (
        'an over-length key and a reserved prefix are different conditions and must not collapse into '
        f"one error code; both said {code_reserved!r}"
    )
    assert msg_long != msg_reserved, (
        'an over-length key and a reserved prefix are different conditions and must not collapse into one '
        f"byte-identical message; both said {msg_reserved!r}"
    )
    assert long_key not in _tag_map(ses, arn), (
        f"a refused over-length tag must not be stored, tags are now {_tag_map(ses, arn)!r}"
    )

    err_batch = _client_error(lambda: ses.tag_resource(ResourceArn=arn, Tags=[
        {'Key': 'sim2real-legal', 'Value': 'should-not-persist'},
        {'Key': 'aws:sim2real-batch', 'Value': 'nope'},
    ]))
    assert err_batch.response['Error']['Code'] == 'BadRequestException', (
        f"a batch containing a reserved key must be refused, got {err_batch.response['Error']!r}"
    )
    assert err_batch.response['Error'].get('Message') == 'Failed to tag resource', (
        f"expected 'Failed to tag resource' for a batch with a reserved key, got {err_batch.response['Error']!r}"
    )
    after_batch = _tag_map(ses, arn)
    assert 'sim2real-legal' not in after_batch, (
        'TagResource must be atomic: the legal tag in a refused batch must not persist. Tags are now '
        f"{after_batch!r}"
    )
    assert 'aws:sim2real-batch' not in after_batch, f"tags are now {after_batch!r}"
    assert after_batch == baseline, (
        f"a refused batch must leave tags exactly as they were: expected {baseline!r}, got {after_batch!r}"
    )

    # A 128-character key at the boundary still succeeds.
    boundary_key = 'b' * 128
    ses.tag_resource(ResourceArn=arn, Tags=[
        {'Key': boundary_key, 'Value': 'at-the-limit'},
        {'Key': 'sim2real-env', 'Value': 'parity'},
    ])
    ctx.on_cleanup(lambda _a=arn, _k=[boundary_key, 'sim2real-env']: ses.untag_resource(
        ResourceArn=_a, TagKeys=_k))
    control = _tag_map(ses, arn)
    assert control.get(boundary_key) == 'at-the-limit', (
        f"a key of exactly 128 characters is legal and must be stored, tags are now {control!r}"
    )
    assert control.get('sim2real-env') == 'parity', f"control tag not stored, tags are now {control!r}"
    assert control.get('sim2real-owner') == 'parity', (
        f"the pre-existing tag must survive, tags are now {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
