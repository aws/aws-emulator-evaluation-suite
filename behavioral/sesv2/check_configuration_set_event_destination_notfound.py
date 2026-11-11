"""configuration-set-event-destination-notfound."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "configuration-set-event-destination-notfound"
GROUP = 'configuration-set'
SERVICES = ['sesv2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating an event destination on a non-existent configuration set MUST fail, an
    independent read must confirm nothing was created, and the identical call must
    succeed once the configuration set exists."""
    ses = ctx.client('sesv2')
    event_destination = {'Enabled': True, 'MatchingEventTypes': ['SEND'], 'CloudWatchDestination': {'DimensionConfigurations': [{'DimensionName': 'sim2realdim', 'DimensionValueSource': 'MESSAGE_TAG', 'DefaultDimensionValue': 'none'}]}}

    control_name = ctx.unique_name('sim2real-behav-cfgset-control-')
    ses.create_configuration_set(ConfigurationSetName=control_name)
    ctx.on_cleanup(lambda _k=control_name: ses.delete_configuration_set(ConfigurationSetName=_k))
    control_dest = ctx.unique_name('sim2real-behav-dest-control-')
    ses.create_configuration_set_event_destination(ConfigurationSetName=control_name, EventDestinationName=control_dest, EventDestination=event_destination)
    ctx.on_cleanup(lambda _k=(control_name, control_dest): ses.delete_configuration_set_event_destination(ConfigurationSetName=_k[0], EventDestinationName=_k[1]))
    control_got = ses.get_configuration_set_event_destinations(ConfigurationSetName=control_name)
    control_names = [d['Name'] for d in control_got['EventDestinations']]
    assert control_dest in control_names, f'positive control failed: {control_dest} not found in {control_names}'

    missing_name = ctx.unique_name('sim2real-behav-cfgset-missing-')
    dest_name = ctx.unique_name('sim2real-behav-dest-')
    expected = ('NotFoundException', f'Configuration set <{missing_name}> does not exist.')
    err = _error(lambda: ses.create_configuration_set_event_destination(ConfigurationSetName=missing_name, EventDestinationName=dest_name, EventDestination=event_destination))
    assert err == expected, f'expected {expected} creating an event destination on a missing configuration set, got {err!r}'

    read_err = _error(lambda: ses.get_configuration_set_event_destinations(ConfigurationSetName=missing_name))
    assert read_err == expected, f'expected {expected} reading event destinations on a missing configuration set, got {read_err!r}'

    ses.create_configuration_set(ConfigurationSetName=missing_name)
    ctx.on_cleanup(lambda _k=missing_name: ses.delete_configuration_set(ConfigurationSetName=_k))
    ses.create_configuration_set_event_destination(ConfigurationSetName=missing_name, EventDestinationName=dest_name, EventDestination=event_destination)
    ctx.on_cleanup(lambda _k=(missing_name, dest_name): ses.delete_configuration_set_event_destination(ConfigurationSetName=_k[0], EventDestinationName=_k[1]))
    restored_got = ses.get_configuration_set_event_destinations(ConfigurationSetName=missing_name)
    restored_names = [d['Name'] for d in restored_got['EventDestinations']]
    assert dest_name in restored_names, f'identical call after creating the configuration set failed: {dest_name} not found in {restored_names}'


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
