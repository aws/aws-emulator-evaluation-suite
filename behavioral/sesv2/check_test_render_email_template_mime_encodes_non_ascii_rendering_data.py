"""test-render-email-template-mime-encodes-non-ascii-rendering-data."""
from __future__ import annotations

import email
import email.header
import json

from behavioral_harness import tags

CHECK = "test-render-email-template-mime-encodes-non-ascii-rendering-data"
GROUP = 'templates'
SERVICES = ['sesv2']

_NON_ASCII = 'café-日本'


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
    """The transfer encoding follows the rendered data: ASCII data renders 7bit with a literal Subject,
    non-ASCII data renders quoted-printable with an RFC 2047 encoded-word Subject that decodes back.
    """
    ses = ctx.client('sesv2')

    name = ctx.unique_name('sim2real-behav-mimeenc-')
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={
            'Subject': 'subj {{v}}',
            'Text': 'text {{v}}',
            'Html': '<p>html {{v}}</p>',
        },
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_email_template(TemplateName=_n))

    ascii_msg = _mime(ses.test_render_email_template(
        TemplateName=name, TemplateData=json.dumps({'v': 'plain'}))['RenderedTemplate'])
    wide_msg = _mime(ses.test_render_email_template(
        TemplateName=name, TemplateData=json.dumps({'v': _NON_ASCII}))['RenderedTemplate'])

    ascii_parts = ascii_msg.get_payload()
    wide_parts = wide_msg.get_payload()

    assert ascii_msg['Subject'] == 'subj plain', (
        f'ASCII rendering data must produce a literal Subject header, got {ascii_msg["Subject"]!r}'
    )
    assert [p['Content-Transfer-Encoding'] for p in ascii_parts] == ['7bit', '7bit'], (
        'ASCII rendering data must leave both parts 7bit, got '
        f'{[p["Content-Transfer-Encoding"] for p in ascii_parts]!r}'
    )

    assert [p['Content-Transfer-Encoding'] for p in wide_parts] == ['quoted-printable', 'quoted-printable'], (
        'non-ASCII rendering data must move both parts off 7bit onto quoted-printable, got '
        f'{[p["Content-Transfer-Encoding"] for p in wide_parts]!r}'
    )
    assert [_part_text(p) for p in wide_parts] == [f'text {_NON_ASCII}', f'<p>html {_NON_ASCII}</p>'], (
        'the quoted-printable parts must decode back to exactly the substituted UTF-8 text, got '
        f'{[_part_text(p) for p in wide_parts]!r}'
    )
    raw_subject = wide_msg['Subject']
    assert raw_subject.startswith('=?UTF-8?') and raw_subject.endswith('?='), (
        'a non-ASCII rendered subject must be emitted as an RFC 2047 UTF-8 encoded-word, not as raw '
        f'bytes, got {raw_subject!r}'
    )
    decoded_subject = str(email.header.make_header(email.header.decode_header(raw_subject)))
    assert decoded_subject == f'subj {_NON_ASCII}', (
        f'the encoded-word Subject must decode back to the rendered subject, got {decoded_subject!r} '
        f'from {raw_subject!r}'
    )
    assert _NON_ASCII not in raw_subject, (
        f'the encoded Subject header must contain no raw non-ASCII bytes, got {raw_subject!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
