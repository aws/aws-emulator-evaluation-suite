"""configuration-set-suppression-options-scope."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "configuration-set-suppression-options-scope"
GROUP = 'suppression'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutConfigurationSetSuppressionOptions is scoped to its own configuration set.

    Suppression options put on one configuration set must not appear on a sibling
    configuration set, and must not be disturbed by a later put on that sibling.
    """
    ses = ctx.client('sesv2')
    name_a = ctx.unique_name('sim2real-behav-cfgset-suppress-a-')
    name_b = ctx.unique_name('sim2real-behav-cfgset-suppress-b-')
    ses.create_configuration_set(ConfigurationSetName=name_a, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda _k=name_a: ses.delete_configuration_set(ConfigurationSetName=_k))
    ses.create_configuration_set(ConfigurationSetName=name_b, Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda _k=name_b: ses.delete_configuration_set(ConfigurationSetName=_k))

    ses.put_configuration_set_suppression_options(ConfigurationSetName=name_a, SuppressedReasons=['BOUNCE', 'COMPLAINT'])
    reasons_a = set(ses.get_configuration_set(ConfigurationSetName=name_a).get('SuppressionOptions', {}).get('SuppressedReasons', []))
    assert reasons_a == {'BOUNCE', 'COMPLAINT'}, f'expected configuration set A to carry both reasons, got {reasons_a}'

    reasons_b = ses.get_configuration_set(ConfigurationSetName=name_b).get('SuppressionOptions', {}).get('SuppressedReasons')
    assert not reasons_b, f"configuration set B must not inherit A's suppression options, got {reasons_b!r}"

    ses.put_configuration_set_suppression_options(ConfigurationSetName=name_b, SuppressedReasons=['COMPLAINT'])
    reasons_b2 = set(ses.get_configuration_set(ConfigurationSetName=name_b).get('SuppressionOptions', {}).get('SuppressedReasons', []))
    assert reasons_b2 == {'COMPLAINT'}, f'expected configuration set B to carry its own reason, got {reasons_b2}'

    reasons_a2 = set(ses.get_configuration_set(ConfigurationSetName=name_a).get('SuppressionOptions', {}).get('SuppressedReasons', []))
    assert reasons_a2 == {'BOUNCE', 'COMPLAINT'}, f"configuration set A must be unaffected by B's put, got {reasons_a2}"
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
