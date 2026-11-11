"""test-render-email-template-selects-the-mime-type-from-the-stored-parts."""
from __future__ import annotations

import email

from behavioral_harness import tags

CHECK = "test-render-email-template-selects-the-mime-type-from-the-stored-parts"
GROUP = 'templates'
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


def _render(ses, ctx, label, content, data):
    """Store a template, render it, and return the parsed message."""
    name = ctx.unique_name(f'sim2real-behav-mimesel-{label}-')
    ses.create_email_template(
        TemplateName=name,
        TemplateContent=content,
        Tags=[{'Key': 'sim2real-check', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_email_template(TemplateName=_n))
    return _mime(ses.test_render_email_template(TemplateName=name, TemplateData=data)['RenderedTemplate'])


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """The rendered MIME container follows the stored parts: Text-only renders flat text/plain with no
    boundary, Html-only renders flat text/html, and only both parts are wrapped in multipart/alternative.
    """
    ses = ctx.client('sesv2')

    text_only = _render(ses, ctx, 'txt', {'Subject': 'subj {{v}}', 'Text': 'only plain {{v}}'}, '{"v": "V"}')
    html_only = _render(ses, ctx, 'html', {'Subject': 'subj {{v}}', 'Html': '<p>only html {{v}}</p>'}, '{"v": "V"}')
    both = _render(
        ses, ctx, 'both',
        {'Subject': 'subj {{v}}', 'Text': 'plain {{v}}', 'Html': '<p>html {{v}}</p>'},
        '{"v": "V"}',
    )

    assert (text_only.get_content_type(), text_only.is_multipart()) == ('text/plain', False), (
        'a template holding only a Text part must render as a flat text/plain message, got '
        f'{text_only.get_content_type()!r} multipart={text_only.is_multipart()!r}'
    )
    assert text_only.get_boundary() is None, (
        f'a flat message must carry no MIME boundary, got {text_only.get_boundary()!r}'
    )
    assert _part_text(text_only) == 'only plain V', (
        f'the flat text/plain body must be the rendered Text template, got {_part_text(text_only)!r}'
    )

    assert (html_only.get_content_type(), html_only.is_multipart()) == ('text/html', False), (
        'a template holding only an Html part must render as a flat text/html message -- not text/plain '
        f'and not multipart -- got {html_only.get_content_type()!r} multipart={html_only.is_multipart()!r}'
    )
    assert _part_text(html_only) == '<p>only html V</p>', (
        f'the flat text/html body must be the rendered Html template, got {_part_text(html_only)!r}'
    )

    assert both.get_content_type() == 'multipart/alternative', (
        'only a template holding both parts is wrapped, and it must be wrapped in multipart/alternative, '
        f'got {both.get_content_type()!r}'
    )
    assert [p.get_content_type() for p in both.get_payload()] == ['text/plain', 'text/html'], (
        f'the wrapped message must hold exactly the two stored parts, got '
        f'{[p.get_content_type() for p in both.get_payload()]!r}'
    )
    assert {m.get_content_charset() for m in (text_only, html_only)} == {'utf-8'}, (
        'every rendered part declares charset UTF-8, got '
        f'{[m.get_content_charset() for m in (text_only, html_only)]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
