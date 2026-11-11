"""configuration-set-duplicate-create."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "configuration-set-duplicate-create"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']

def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as _e:
        _err = _e.response.get('Error', {})
        return (_err.get('Code'), _err.get('Message'))
    raise AssertionError(f'expected a ClientError, the call succeeded with {result!r}')


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a configuration set with a name that already exists MUST fail, the collision
    must leave the original set untouched, and deleting it must free the name again."""
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-cfgset-dup-')
    ses.create_configuration_set(ConfigurationSetName=name, Tags=[{'Key': 'sim2real', 'Value': 'configuration-set-duplicate-create'}])
    ctx.on_cleanup(lambda _k=name: ses.delete_configuration_set(ConfigurationSetName=_k))

    err = _error(lambda: ses.create_configuration_set(ConfigurationSetName=name))
    expected = ('AlreadyExistsException', f'Configuration set <{name}> already exists.')
    assert err == expected, f'expected {expected}, got {err}'

    # Effect absent: the rejected duplicate call did not touch the original set -- an
    # independent read still shows it under the same name.
    current = ses.get_configuration_set(ConfigurationSetName=name)
    assert current['ConfigurationSetName'] == name, f"expected {name!r} still present after the rejected duplicate, got {current.get('ConfigurationSetName')!r}"

    # Restore: deleting the original frees the name, and the identical call now succeeds --
    # proving AlreadyExistsException was about the collision, not a permanent block on the name.
    ses.delete_configuration_set(ConfigurationSetName=name)
    not_found = _error(lambda: ses.get_configuration_set(ConfigurationSetName=name))
    expected_nf = ('NotFoundException', f'Configuration set <{name}> does not exist.')
    assert not_found == expected_nf, f'expected {expected_nf} from get after delete, got {not_found}'

    ses.create_configuration_set(ConfigurationSetName=name)
    recreated = ses.get_configuration_set(ConfigurationSetName=name)
    assert recreated['ConfigurationSetName'] == name, f'expected deleted name {name!r} to be reusable, got {recreated.get("ConfigurationSetName")!r}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
