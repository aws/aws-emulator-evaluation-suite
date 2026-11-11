"""test-render-with-incomplete-template-data-rejected-complete-data-renders."""
from __future__ import annotations

import email
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "test-render-with-incomplete-template-data-rejected-complete-data-renders"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']


def _mime(rendered: str):
    """Parse a TestRenderEmailTemplate result as the MIME message it actually is."""
    msg = email.message_from_string(rendered)
    assert msg.defects == [], f'the rendered template is not a well-formed MIME message: {msg.defects!r}'
    return msg


def _part_text(part) -> str:
    raw = part.get_payload(decode=True)
    assert raw is not None, f'part {part.get_content_type()!r} carries no decodable payload'
    return raw.decode(part.get_content_charset() or 'utf-8')


def _client_error(fn) -> ClientError:
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f'the call was expected to be refused but it succeeded: {result!r}')


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """TestRenderEmailTemplate refuses data missing a referenced placeholder with BadRequestException
    naming it, leaves the stored template unchanged, and renders once the attribute is supplied.
    """
    ses = ctx.client('sesv2')

    name = ctx.unique_name('sim2real-behav-render-incomplete-')
    content = {
        'Subject': 'Hi {{name}}',
        'Text': 'Hi {{name}}, ref {{required_field}}',
        'Html': '<p>{{required_field}}</p>',
    }
    ses.create_email_template(
        TemplateName=name, TemplateContent=content, Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_email_template(TemplateName=_n))
    stored_before = ses.get_email_template(TemplateName=name)['TemplateContent']

    err = _client_error(lambda: ses.test_render_email_template(
        TemplateName=name, TemplateData=json.dumps({'name': 'Ada'})))
    code = err.response['Error']['Code']
    message = err.response['Error'].get('Message') or ''
    assert code == 'BadRequestException', (
        f'rendering data that omits a referenced placeholder must be refused with BadRequestException, '
        f'got {code!r}: {message!r}'
    )
    assert message == "Attribute 'required_field' is not present in the rendering data.", (
        'the refusal must name the attribute that was missing, otherwise a caller cannot fix the call; '
        f'got {message!r}'
    )

    stored_after = ses.get_email_template(TemplateName=name)['TemplateContent']
    assert stored_after == stored_before == content, (
        f'the refused render mutated the stored template: {stored_before!r} -> {stored_after!r}'
    )

    rendered = ses.test_render_email_template(
        TemplateName=name,
        TemplateData=json.dumps({'name': 'Ada', 'required_field': 'supplied-value'}),
    )['RenderedTemplate']
    msg = _mime(rendered)
    html_part = msg.get_payload()[1]
    assert _part_text(html_part) == '<p>supplied-value</p>', (
        'the control render must substitute the previously-missing attribute into the text/html part, got '
        f'{_part_text(html_part)!r}'
    )
    assert msg['Subject'] == 'Hi Ada', (
        f'the control render must still render the subject, got {msg["Subject"]!r}'
    )
    assert '{{required_field}}' not in rendered, (
        f'the placeholder survived the successful render: {rendered!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
