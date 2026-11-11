"""test-render-email-template-does-not-html-escape-substituted-values."""
from __future__ import annotations

import email
import json

from behavioral_harness import tags

CHECK = "test-render-email-template-does-not-html-escape-substituted-values"
GROUP = 'templates'
SERVICES = ['sesv2']

# Every character stock Handlebars HTML-escapes by default; SES escapes none of them.
_MARKUP = '<b>&"x"\'y\'</b>'
_ENTITIES = ('&lt;', '&gt;', '&amp;', '&quot;', '&#x27;', '&#39;', '&#x60;')


def _mime(rendered: str):
    """Parse a TestRenderEmailTemplate result as the MIME message it actually is."""
    msg = email.message_from_string(rendered)
    assert msg.defects == [], f'the rendered template is not a well-formed MIME message: {msg.defects!r}'
    return msg


def _part_text(part) -> str:
    raw = part.get_payload(decode=True)
    assert raw is not None, f'part {part.get_content_type()!r} carries no decodable payload'
    return raw.decode(part.get_content_charset() or 'utf-8')


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """SES substitutes template values verbatim: `{{v}}` and triple-stash `{{{v}}}` both render the raw
    value without HTML-escaping, in the subject and both body parts.
    """
    ses = ctx.client('sesv2')

    name = ctx.unique_name('sim2real-behav-noesc-')
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={
            'Subject': 'S {{v}}',
            'Text': 'esc={{v}} raw={{{v}}}',
            'Html': '<p>esc={{v}} raw={{{v}}}</p>',
        },
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_email_template(TemplateName=_n))

    raw = ses.test_render_email_template(
        TemplateName=name, TemplateData=json.dumps({'v': _MARKUP}))['RenderedTemplate']
    msg = _mime(raw)
    text_part, html_part = msg.get_payload()

    assert _part_text(text_part) == f'esc={_MARKUP} raw={_MARKUP}', (
        'the text/plain part must carry the value verbatim under both stash forms, got '
        f'{_part_text(text_part)!r}'
    )
    assert _part_text(html_part) == f'<p>esc={_MARKUP} raw={_MARKUP}</p>', (
        'the text/html part must carry the value verbatim under both stash forms -- this is the part where a '
        f'Handlebars-backed emulator will escape -- got {_part_text(html_part)!r}'
    )
    assert msg['Subject'] == f'S {_MARKUP}', (
        f'the rendered Subject header must carry the value verbatim, got {msg["Subject"]!r}'
    )
    leaked = [e for e in _ENTITIES if e in raw]
    assert leaked == [], (
        f'the renderer emitted HTML entities {leaked!r}, so it escaped the substituted value; the whole '
        f'rendered message was {raw!r}'
    )
    assert raw.count(_MARKUP) == 5, (
        'the value is referenced once in the subject and twice in each of the two body parts, so it must '
        f'occur verbatim exactly five times in the message; got {raw.count(_MARKUP)} in {raw!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
