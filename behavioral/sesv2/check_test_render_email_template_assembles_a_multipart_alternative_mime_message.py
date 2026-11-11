"""test-render-email-template-assembles-a-multipart-alternative-mime-message."""
from __future__ import annotations

import email

from behavioral_harness import tags

CHECK = "test-render-email-template-assembles-a-multipart-alternative-mime-message"
GROUP = 'templates'
SERVICES = ['sesv2']

# The MIME envelope is parsed rather than split on the boundary, which is minted per render.


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
    """TestRenderEmailTemplate returns a complete multipart/alternative MIME message: rendered Subject,
    MIME-Version 1.0, text/plain before text/html, and a freshly minted boundary on every call.
    """
    ses = ctx.client('sesv2')

    name = ctx.unique_name('sim2real-behav-mime-')
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={
            'Subject': 'Hi {{name}}',
            'Text': 'plain {{name}}',
            'Html': '<p>html {{name}}</p>',
        },
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_email_template(TemplateName=_n))

    first_raw = ses.test_render_email_template(TemplateName=name, TemplateData='{"name": "Ada"}')['RenderedTemplate']
    second_raw = ses.test_render_email_template(TemplateName=name, TemplateData='{"name": "Ada"}')['RenderedTemplate']

    first = _mime(first_raw)
    second = _mime(second_raw)

    assert first.get_content_type() == 'multipart/alternative', (
        'a template carrying both a Text and an Html part must render as a multipart/alternative message, '
        f'got Content-Type {first.get("Content-Type")!r}'
    )
    parts = first.get_payload()
    assert [p.get_content_type() for p in parts] == ['text/plain', 'text/html'], (
        'multipart/alternative orders parts least-rich first, so the text/plain part must precede the '
        f'text/html part; got {[p.get_content_type() for p in parts]!r}'
    )
    assert first['Subject'] == 'Hi Ada', (
        f'the Subject header must carry the rendered subject, got {first["Subject"]!r}'
    )
    assert first['MIME-Version'] == '1.0', (
        f'an assembled MIME message must declare MIME-Version 1.0, got {first["MIME-Version"]!r}'
    )
    assert _part_text(parts[0]) == 'plain Ada', (
        f'the text/plain part must be the rendered Text template, got {_part_text(parts[0])!r}'
    )
    assert _part_text(parts[1]) == '<p>html Ada</p>', (
        f'the text/html part must be the rendered Html template, got {_part_text(parts[1])!r}'
    )
    assert '{{' not in first_raw, f'an unsubstituted placeholder survived the render: {first_raw!r}'

    boundaries = (first.get_boundary(), second.get_boundary())
    assert boundaries[0] and boundaries[1] and boundaries[0] != boundaries[1], (
        'each render assembles a new MIME message and must mint its own boundary, got the same token '
        f'twice: {boundaries!r}'
    )
    assert [_part_text(p) for p in second.get_payload()] == ['plain Ada', '<p>html Ada</p>'], (
        'the second render of unchanged template and unchanged data must produce identical parts, got '
        f'{[_part_text(p) for p in second.get_payload()]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
