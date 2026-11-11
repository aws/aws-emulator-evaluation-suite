"""send-bulk-email-missing-default-template-data-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "send-bulk-email-missing-default-template-data-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendBulkEmail with inline template content but no TemplateData fails as a whole request with
    BadRequestException, while the same call with TemplateData clears that gate.
    """
    ses = ctx.client('sesv2')
    sender = ctx.unique_name('sim2real-behav-bulk-sender-') + '@example.com'
    entries = [{'Destination': {'ToAddresses': [f'success+{i}@simulator.amazonses.com']}} for i in range(3)]

    def _send(*, template_data_present):
        template = {'TemplateContent': {'Subject': 'Bulk subject', 'Text': 'Bulk body'}}
        if template_data_present:
            template['TemplateData'] = '{}'
        try:
            result = ses.send_bulk_email(FromEmailAddress=sender, DefaultContent={'Template': template}, BulkEmailEntries=entries)
        except ClientError as _e:
            return _e.response['Error']['Code'], _e.response['Error'].get('Message')
        raise AssertionError(f'expected SendBulkEmail from an unverified sender to be rejected, but it SUCCEEDED and returned {result!r}')

    # The sender is unverified, so the control cannot succeed; it must only not fail on this gate.
    control_code, _control_message = _send(template_data_present=True)
    assert control_code != 'BadRequestException', f'positive control: supplying TemplateData must clear the missing-TemplateData gate, got {control_code}'

    err = _send(template_data_present=False)
    expected = ('BadRequestException', 'The default template data does not exist')
    assert err == expected, f'expected {expected!r}, got {err!r}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
