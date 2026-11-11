"""updating-a-template-changes-what-the-renderer-produces."""
from __future__ import annotations

import email
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "updating-a-template-changes-what-the-renderer-produces"
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


def _settle(fn, *, timeout_s=60.0, interval_s=2.0):
    """Poll fn() until it returns something truthy; raise on deadline miss."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = fn()
        if last:
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f'the condition was not reached within {timeout_s}s; last observation was {last!r}')
        time.sleep(interval_s)


def _client_error(fn) -> ClientError:
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f'the call was expected to be refused but it succeeded: {result!r}')


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """UpdateEmailTemplate changes what TestRenderEmailTemplate produces: the new body renders, the
    old body is gone, the old data is refused for the missing new placeholder, and restoring the
    old placeholder makes that identical render succeed again.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_TestRenderEmailTemplate.html
    """
    ses = ctx.client('sesv2')

    name = ctx.unique_name('sim2real-behav-tplupd-')
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={'Subject': 'subj', 'Text': 'v1 {{a}}', 'Html': '<p>v1 {{a}}</p>'},
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_email_template(TemplateName=_n))

    first = _mime(ses.test_render_email_template(
        TemplateName=name, TemplateData='{"a": "x"}')['RenderedTemplate'])
    assert [_part_text(p) for p in first.get_payload()] == ['v1 x', '<p>v1 x</p>'], (
        f'the initial render is wrong: {[_part_text(p) for p in first.get_payload()]!r}'
    )

    ses.update_email_template(
        TemplateName=name,
        TemplateContent={'Subject': 'subj', 'Text': 'v2 {{b}}', 'Html': '<p>v2 {{b}}</p>'},
    )

    # Wait until the renderer serves the new body; a refusal taken before then would prove nothing.
    def _new_body_renders():
        try:
            return ses.test_render_email_template(
                TemplateName=name, TemplateData='{"b": "y"}')['RenderedTemplate']
        except ClientError:
            return None

    second = _mime(_settle(_new_body_renders))
    assert [_part_text(p) for p in second.get_payload()] == ['v2 y', '<p>v2 y</p>'], (
        f'the renderer did not pick up the update: {[_part_text(p) for p in second.get_payload()]!r}'
    )
    assert 'v1' not in ''.join(_part_text(p) for p in second.get_payload()), (
        f'the old body survived the update: {[_part_text(p) for p in second.get_payload()]!r}'
    )

    err = _client_error(lambda: ses.test_render_email_template(
        TemplateName=name, TemplateData='{"a": "x"}'))
    code = err.response['Error']['Code']
    message = err.response['Error'].get('Message') or ''
    assert (code, message) == (
        'BadRequestException',
        "Attribute 'b' is not present in the rendering data.",
    ), (
        f'rendering the updated template with the pre-update data must be refused with '
        f'BadRequestException naming the unsatisfied placeholder `b`, got {code!r}: {message!r}'
    )

    # Restore `a`: the identical refused call must now succeed.
    ses.update_email_template(
        TemplateName=name,
        TemplateContent={'Subject': 'subj', 'Text': 'v3 {{a}}', 'Html': '<p>v3 {{a}}</p>'},
    )

    def _restored_body_renders():
        try:
            return ses.test_render_email_template(
                TemplateName=name, TemplateData='{"a": "x"}')['RenderedTemplate']
        except ClientError:
            return None

    third = _mime(_settle(_restored_body_renders))
    assert [_part_text(p) for p in third.get_payload()] == ['v3 x', '<p>v3 x</p>'], (
        f'restoring the `a` placeholder did not make the identical call succeed: '
        f'{[_part_text(p) for p in third.get_payload()]!r}'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
