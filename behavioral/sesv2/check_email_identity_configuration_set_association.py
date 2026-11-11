"""email-identity-configuration-set-association."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "email-identity-configuration-set-association"
GROUP = 'identity'
SERVICES = ['sesv2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a non-existent configuration set with an identity MUST fail with NotFound."""
    ses = ctx.client('sesv2')
    email = ctx.unique_name('sim2real-behav-identity-cfg-') + '@example.com'
    ses.create_email_identity(EmailIdentity=email, Tags=[{'Key': 'sim2real', 'Value': 'behav-identity-cfg'}])
    ctx.on_cleanup(lambda _k=email: ses.delete_email_identity(EmailIdentity=_k))
    cfg_name = ctx.unique_name('sim2real-behav-cfgset-assoc-')
    ses.create_configuration_set(ConfigurationSetName=cfg_name, Tags=[{'Key': 'sim2real', 'Value': 'behav-identity-cfg'}])
    ctx.on_cleanup(lambda _k=cfg_name: ses.delete_configuration_set(ConfigurationSetName=_k))
    ses.put_email_identity_configuration_set_attributes(EmailIdentity=email, ConfigurationSetName=cfg_name)
    got = ses.get_email_identity(EmailIdentity=email)
    assert got.get('ConfigurationSetName') == cfg_name, f"expected {cfg_name!r}, got {got.get('ConfigurationSetName')!r}"
    missing_cfg = ctx.unique_name('sim2real-behav-cfgset-missing-')
    err = _error(lambda: ses.put_email_identity_configuration_set_attributes(EmailIdentity=email, ConfigurationSetName=missing_cfg))
    assert err.get('Code') == 'NotFoundException', f'expected NotFoundException, got {err!r}'
    expected = f'Configuration set <{missing_cfg}> does not exist.'
    assert err.get('Message') == expected, f"expected message {expected!r}, got {err.get('Message')!r}"
    after = ses.get_email_identity(EmailIdentity=email)
    assert after.get('ConfigurationSetName') == cfg_name, f"rejected association mutated state: expected unchanged {cfg_name!r}, got {after.get('ConfigurationSetName')!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
