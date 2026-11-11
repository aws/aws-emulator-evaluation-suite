"""duplicate-template-create-rejected-and-the-original-body-still-renders."""
from __future__ import annotations

import email
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-template-create-rejected-and-the-original-body-still-renders"
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


def _delete_if_present(ses, name):
    try:
        ses.delete_email_template(TemplateName=name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != 'NotFoundException':
            raise


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """CreateEmailTemplate on an existing name fails with AlreadyExistsException and is not a hidden
    upsert: the render and GetEmailTemplate still show the original body and subject afterwards.
    """
    ses = ctx.client('sesv2')

    original_marker = f'original-{uuid.uuid4().hex}'
    overwrite_marker = f'overwrite-{uuid.uuid4().hex}'
    original_html = f'<p>{original_marker}</p>'

    name = ctx.unique_name('sim2real-behav-tpldup-')
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={'Subject': 'original-subject', 'Text': original_marker, 'Html': original_html},
    )
    # Registered before the duplicate attempt: if the service wrongly ACCEPTS the duplicate, the resource
    # still exists under this same name and this cleanup is the one that removes it.
    ctx.on_cleanup(lambda _n=name: _delete_if_present(ses, _n))

    def _overwrite_create():
        return ses.create_email_template(
            TemplateName=name,
            TemplateContent={
                'Subject': 'overwrite-subject',
                'Text': overwrite_marker,
                'Html': f'<p>{overwrite_marker}</p>',
            },
        )

    err = _client_error(_overwrite_create)
    code = err.response['Error']['Code']
    status = err.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    message = err.response['Error'].get('Message') or ''
    assert code == 'AlreadyExistsException', (
        f'a duplicate template name must be refused with AlreadyExistsException, got {code!r}: {message!r}'
    )
    assert status == 400, f'expected HTTP 400 for the duplicate create, got {status!r}'
    expected_message = f"Template {name} already exists for account id {ctx.account}"
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    # The render carries a per-call Date and MIME boundary, so compare decoded parts, not bytes.
    msg = _mime(ses.test_render_email_template(TemplateName=name, TemplateData='{}')['RenderedTemplate'])
    parts = [_part_text(p) for p in msg.get_payload()]
    assert parts == [original_marker, original_html], (
        f'the render after the refused create must reproduce the original body, got {parts!r}'
    )
    assert overwrite_marker not in ''.join(parts), (
        f'the refused create overwrote the stored body: the render emitted {parts!r}'
    )
    assert msg['Subject'] == 'original-subject', (
        f'the refused create replaced the stored subject, the render emitted {msg["Subject"]!r}'
    )

    # And directly, so a renderer that ignores the store cannot hide the same defect.
    stored = ses.get_email_template(TemplateName=name)['TemplateContent']
    assert stored['Html'] == original_html, (
        f'the stored Html changed after the refused create: {stored!r}'
    )

    ses.delete_email_template(TemplateName=name)
    _overwrite_create()
    msg = _mime(ses.test_render_email_template(TemplateName=name, TemplateData='{}')['RenderedTemplate'])
    parts = [_part_text(p) for p in msg.get_payload()]
    assert parts == [overwrite_marker, f'<p>{overwrite_marker}</p>'], (
        f'the identical create after the delete must store the new body, the render emitted {parts!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
