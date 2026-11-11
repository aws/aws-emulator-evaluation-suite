"""template-render-missing-variable-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "template-render-missing-variable-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Rendering a template without supplying a variable it requires MUST fail."""
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-tmpl-missingvar-')
    ses.create_email_template(TemplateName=name, TemplateContent={'Subject': 'Hi {{name}}', 'Text': 'Body requires {{required_field}} to render'})
    ctx.on_cleanup(lambda _k=name: ses.delete_email_template(TemplateName=_k))

    control = ses.test_render_email_template(TemplateName=name, TemplateData='{"name": "Bob", "required_field": "present"}')['RenderedTemplate']
    assert 'present' in control and '{{required_field}}' not in control, f'positive control did not substitute required_field: {control!r}'

    try:
        result = ses.test_render_email_template(TemplateName=name, TemplateData='{"name": "Bob"}')
    except ClientError as _e:
        code = _e.response.get('Error', {}).get('Code')
        msg = _e.response.get('Error', {}).get('Message')
    else:
        raise AssertionError(f'expected a missing variable to be rejected, but the render succeeded: {result!r}')
    assert code == 'BadRequestException', f'expected BadRequestException, got {code}'
    expected_msg = "Attribute 'required_field' is not present in the rendering data."
    assert msg == expected_msg, f'expected message {expected_msg!r}, got {msg!r}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
