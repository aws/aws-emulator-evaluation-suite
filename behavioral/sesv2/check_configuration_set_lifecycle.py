"""configuration-set-lifecycle."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "configuration-set-lifecycle"
GROUP = 'configuration-set'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create -> get -> delete -> get(NotFoundException) -> mutate(NotFoundException) -> recreate (name reusable)."""
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-cfgset-')

    ses.create_configuration_set(ConfigurationSetName=name, Tags=[{'Key': 'sim2real', 'Value': 'configuration-set-lifecycle'}])
    ctx.on_cleanup(lambda _k=name: ses.delete_configuration_set(ConfigurationSetName=_k))
    got = ses.get_configuration_set(ConfigurationSetName=name)
    assert got['ConfigurationSetName'] == name, f"expected ConfigurationSetName {name!r}, got {got.get('ConfigurationSetName')!r}"

    ses.delete_configuration_set(ConfigurationSetName=name)
    expected = ('NotFoundException', f'Configuration set <{name}> does not exist.')
    err = _error(lambda: ses.get_configuration_set(ConfigurationSetName=name))
    assert err == expected, f'expected {expected} from get after delete, got {err}'

    err = _error(lambda: ses.put_configuration_set_sending_options(ConfigurationSetName=name, SendingEnabled=True))
    assert err == expected, f'expected {expected} mutating a deleted configuration set, got {err}'

    ses.create_configuration_set(ConfigurationSetName=name)
    got = ses.get_configuration_set(ConfigurationSetName=name)
    assert got['ConfigurationSetName'] == name, f'expected deleted name {name!r} to be reusable, got {got.get("ConfigurationSetName")!r}'


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as _e:
        _err = _e.response.get('Error', {})
        return (_err.get('Code'), _err.get('Message'))
    raise AssertionError(f'expected a ClientError, the call succeeded with {result!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
