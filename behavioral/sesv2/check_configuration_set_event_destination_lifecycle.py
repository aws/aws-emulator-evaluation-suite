"""configuration-set-event-destination-lifecycle."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "configuration-set-event-destination-lifecycle"
GROUP = 'configuration-set'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create -> get -> delete event destination on a configuration set, then reject a
    CloudWatch destination whose DimensionValueSource casing doesn't match the enum."""
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-cfgset-ed-')
    ses.create_configuration_set(ConfigurationSetName=name)
    ctx.on_cleanup(lambda _k=name: ses.delete_configuration_set(ConfigurationSetName=_k))
    dest_name = ctx.unique_name('sim2real-behav-dest-')
    event_destination = {'Enabled': True, 'MatchingEventTypes': ['SEND', 'BOUNCE'], 'CloudWatchDestination': {'DimensionConfigurations': [{'DimensionName': 'sim2realdim', 'DimensionValueSource': 'MESSAGE_TAG', 'DefaultDimensionValue': 'none'}]}}
    ses.create_configuration_set_event_destination(ConfigurationSetName=name, EventDestinationName=dest_name, EventDestination=event_destination)
    ctx.on_cleanup(lambda _k=(name, dest_name): _tolerate_missing(lambda: ses.delete_configuration_set_event_destination(ConfigurationSetName=_k[0], EventDestinationName=_k[1])))
    got = ses.get_configuration_set_event_destinations(ConfigurationSetName=name)
    names = [d['Name'] for d in got['EventDestinations']]
    assert dest_name in names, f'{dest_name} not found in {names}'
    ses.delete_configuration_set_event_destination(ConfigurationSetName=name, EventDestinationName=dest_name)
    got_after = ses.get_configuration_set_event_destinations(ConfigurationSetName=name)
    names_after = [d['Name'] for d in got_after.get('EventDestinations', [])]
    assert dest_name not in names_after, f'{dest_name} still present after delete'
    bad_dest_name = ctx.unique_name('sim2real-behav-dest-bad-')
    err = _error(lambda: ses.create_configuration_set_event_destination(ConfigurationSetName=name, EventDestinationName=bad_dest_name, EventDestination={'Enabled': True, 'MatchingEventTypes': ['SEND'], 'CloudWatchDestination': {'DimensionConfigurations': [{'DimensionName': 'sim2realdim', 'DimensionValueSource': 'messageTag', 'DefaultDimensionValue': 'none'}]}}))
    expected = ('BadRequestException', 'invalid CloudWatch dimension source')
    assert err == expected, f'expected {expected}, got {err}'
    got_bad = ses.get_configuration_set_event_destinations(ConfigurationSetName=name)
    names_bad = [d['Name'] for d in got_bad.get('EventDestinations', [])]
    assert bad_dest_name not in names_bad, f'{bad_dest_name} present after rejected create in {names_bad}'


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as _e:
        _err = _e.response.get('Error', {})
        return (_err.get('Code'), _err.get('Message'))
    raise AssertionError(f'expected a ClientError, the call succeeded with {result!r}')


def _tolerate_missing(fn):
    """Teardown: run fn, treating NotFoundException as already gone."""
    try:
        fn()
    except ClientError as _e:
        if _e.response.get('Error', {}).get('Code') != 'NotFoundException':
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
