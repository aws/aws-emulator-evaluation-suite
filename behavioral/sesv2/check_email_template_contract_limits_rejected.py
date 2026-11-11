"""email-template-contract-limits-rejected."""
from __future__ import annotations

import json
import re

CHECK = "email-template-contract-limits-rejected"
GROUP = 'templates-v2'
SERVICES = ['sesv2']

from behavioral_harness import tags
from botocore.exceptions import ClientError

# Modeled EmailTemplateData max. Only upper bounds are exercised: botocore rejects below-minimum
# values client-side, but does not validate `max`, so over-limit input reaches the server.
_TEMPLATE_DATA_MAX = 262144
# Unmodeled service quota: the whole template must fit in 500 KB (400 KB accepted, 600 KB refused).
_TEMPLATE_SIZE_MAX_KB = 500
_TEXT_OVER_LIMIT = 600_000
_TEXT_UNDER_LIMIT = 400_000


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError('expected the call to be refused, but it succeeded')


def _template_data(total_len: int) -> str:
    """A JSON rendering-data document of exactly total_len bytes with one key, 'k'."""
    overhead = len(json.dumps({'k': ''}))
    return json.dumps({'k': 'x' * (total_len - overhead)})


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Template rendering data over 262144 bytes and templates over the 500 KB quota are refused with
    distinct messages and nothing is created, while values at or under the limit round-trip intact,
    so large input is neither accepted unbounded nor silently truncated.
    """
    ses = ctx.client('sesv2')

    name = ctx.unique_name('sim2real-behav-tmpllim-')
    ses.create_email_template(
        TemplateName=name,
        TemplateContent={'Subject': 'limit probe', 'Text': 'value={{k}}', 'Html': '<p>value={{k}}</p>'},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}],
    )
    ctx.on_cleanup(lambda _n=name: ses.delete_email_template(TemplateName=_n))

    # --- TemplateData upper bound ---
    over = _template_data(_TEMPLATE_DATA_MAX + 1)
    assert len(over) == _TEMPLATE_DATA_MAX + 1, f"test setup produced {len(over)} bytes"
    err_data = _client_error(lambda: ses.test_render_email_template(TemplateName=name, TemplateData=over))
    code_data = err_data.response['Error']['Code']
    msg_data = err_data.response['Error'].get('Message') or ''
    assert code_data == 'BadRequestException', (
        f"TemplateData of {len(over)} bytes exceeds the modeled maximum of {_TEMPLATE_DATA_MAX} and must be "
        f"refused with BadRequestException, got {code_data!r}: {msg_data!r}"
    )
    expected_data_msg = (
        "1 validation error detected: Value at 'templateData' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_TEMPLATE_DATA_MAX}"
    )
    assert msg_data == expected_data_msg, f"expected message {expected_data_msg!r}, got {msg_data!r}"

    # Boundary control: exactly at the limit must be accepted, and the value must survive intact.
    at_limit = _template_data(_TEMPLATE_DATA_MAX)
    assert len(at_limit) == _TEMPLATE_DATA_MAX, f"test setup produced {len(at_limit)} bytes"
    rendered = ses.test_render_email_template(TemplateName=name, TemplateData=at_limit)['RenderedTemplate']
    # The MIME parts are quoted-printable, so a long value is soft-wrapped with `=\r\n` every <=76
    # octets; un-folding the soft breaks recovers the whole value, once per alternative.
    expected_run = 'x' * (_TEMPLATE_DATA_MAX - len(json.dumps({'k': ''})))
    unfolded = re.sub(r'=\r?\n', '', rendered)
    assert unfolded.count(expected_run) == 2, (
        f"rendering data of exactly {_TEMPLATE_DATA_MAX} bytes must be accepted and substituted "
        f"whole into both the text/plain and text/html alternatives, not truncated away; the "
        f"{len(expected_run)}-character value appears {unfolded.count(expected_run)} time(s) in the "
        f"{len(rendered)}-byte rendering"
    )
    assert 'Content-Transfer-Encoding: quoted-printable' in rendered, (
        f"TestRenderEmailTemplate returns a MIME document with quoted-printable parts, got a "
        f"{len(rendered)}-byte body starting {rendered[:200]!r}"
    )
    for ctype in ('text/plain', 'text/html'):
        assert f'Content-Type: {ctype}' in rendered, (
            f"the rendering must carry both alternatives of the template; {ctype} is missing"
        )

    # --- Template size upper bound: a different limit on a different operation ---
    # AWS does not bound the template subject: EmailTemplateContent.Subject targets the unconstrained
    # EmailTemplateSubject shape, not EmailSubject's 1..998 range.
    long_subject = 's' * 999
    subj_name = ctx.unique_name('sim2real-behav-tmpllim-subj-')
    ses.create_email_template(
        TemplateName=subj_name, TemplateContent={'Subject': long_subject, 'Text': 'body'},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda _n=subj_name: ses.delete_email_template(TemplateName=_n))
    stored_subj = ses.get_email_template(TemplateName=subj_name)['TemplateContent']['Subject']
    assert stored_subj == long_subject, (
        f"a 999-character template subject is legal (EmailTemplateSubject is unconstrained) and must be "
        f"stored intact, got {len(stored_subj)} characters"
    )

    over_name = ctx.unique_name('sim2real-behav-tmpllim-size-')
    err_size = _client_error(lambda: ses.create_email_template(
        TemplateName=over_name,
        TemplateContent={'Subject': 'size probe', 'Text': 'b' * _TEXT_OVER_LIMIT},
    ))
    code_size = err_size.response['Error']['Code']
    msg_size = err_size.response['Error'].get('Message') or ''
    assert code_size == 'BadRequestException', (
        f"a template of {_TEXT_OVER_LIMIT} bytes exceeds the {_TEMPLATE_SIZE_MAX_KB} KB quota and must be "
        f"refused with BadRequestException, got {code_size!r}: {msg_size!r}"
    )
    expected_size_msg = f"Template {over_name} exceeds maximum allowed size of {_TEMPLATE_SIZE_MAX_KB} KB."
    assert msg_size == expected_size_msg, (
        f"the refusal must name the {_TEMPLATE_SIZE_MAX_KB} KB template quota that was breached, so the "
        f"caller can tell it apart from a rendering-data breach; expected {expected_size_msg!r}, got {msg_size!r}"
    )
    assert msg_size != msg_data, (
        'an over-size template and over-length rendering data are different limits and must not collapse '
        f"into one byte-identical BadRequestException; both said {msg_data!r}"
    )

    # Effect absent: the refused CreateEmailTemplate created nothing.
    err_absent = _client_error(lambda: ses.get_email_template(TemplateName=over_name))
    assert err_absent.response['Error']['Code'] == 'NotFoundException', (
        f"a refused CreateEmailTemplate must leave no template behind, got {err_absent.response['Error']!r}"
    )
    expected_absent_msg = f"Template {over_name} does not exist."
    assert err_absent.response['Error'].get('Message') == expected_absent_msg, (
        f"expected message {expected_absent_msg!r}, got {err_absent.response['Error'].get('Message')!r}"
    )

    # Boundary control: a template comfortably under the quota is legal and must round-trip byte-for-byte,
    # so the refusal above is about the size and not about large bodies being truncated or rejected.
    at_name = ctx.unique_name('sim2real-behav-tmpllim-ok-')
    at_text = 'b' * _TEXT_UNDER_LIMIT
    ses.create_email_template(
        TemplateName=at_name, TemplateContent={'Subject': 'size control', 'Text': at_text},
        Tags=[{'Key': 'sim2real', 'Value': CHECK}])
    ctx.on_cleanup(lambda _n=at_name: ses.delete_email_template(TemplateName=_n))
    stored = ses.get_email_template(TemplateName=at_name)['TemplateContent']['Text']
    assert stored == at_text, (
        f"a {_TEXT_UNDER_LIMIT}-byte template body is under the {_TEMPLATE_SIZE_MAX_KB} KB quota and must "
        f"be stored intact, got {len(stored)} characters"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
