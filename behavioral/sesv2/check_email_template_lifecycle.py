"""email-template-lifecycle."""
from __future__ import annotations
import json
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "email-template-lifecycle"
GROUP = 'template'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c3", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create -> get -> update -> render(success) -> delete -> get(NotFound) -> update(NotFound)."""
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-tmpl-')
    ses.create_email_template(TemplateName=name, TemplateContent={'Subject': 'Hello {{name}}', 'Text': 'Hi {{name}}, welcome!'})
    ctx.on_cleanup(lambda _k=name: _ignore_not_found(lambda: ses.delete_email_template(TemplateName=_k)))
    got = ses.get_email_template(TemplateName=name)
    assert got['TemplateContent']['Subject'] == 'Hello {{name}}', f"expected freshly created Subject, got {got['TemplateContent']['Subject']!r}"
    ses.update_email_template(TemplateName=name, TemplateContent={'Subject': 'Updated {{name}}', 'Text': 'Updated body {{name}}'})
    got_after = ses.get_email_template(TemplateName=name)['TemplateContent']
    assert got_after['Subject'] == 'Updated {{name}}', f"expected Subject fully replaced, got {got_after['Subject']!r}"
    assert got_after['Text'] == 'Updated body {{name}}', f"expected Text fully replaced (old content gone), got {got_after['Text']!r}"
    marker = uuid.uuid4().hex
    rendered = ses.test_render_email_template(TemplateName=name, TemplateData=json.dumps({'name': marker}))['RenderedTemplate']
    assert marker in rendered, f'substitution of {marker!r} missing from render: {rendered!r}'
    assert '{{name}}' not in rendered, f'placeholder not substituted: {rendered!r}'
    ses.delete_email_template(TemplateName=name)
    err = _error(lambda: ses.get_email_template(TemplateName=name))
    assert err.get('Code') == 'NotFoundException', f'expected NotFoundException on read after delete, got {err!r}'
    assert err.get('HTTPStatusCode') == 404, f'expected HTTP 404 on read after delete, got {err!r}'
    expected_message = f"Template {name} does not exist."
    assert err.get('Message') == expected_message, f"expected the message {expected_message!r}, got {err.get('Message')!r}"
    assert name not in _template_names(ses), f'deleted template {name!r} is still listed by ListEmailTemplates'
    err = _error(lambda: ses.update_email_template(TemplateName=name, TemplateContent={'Subject': 'ghost', 'Text': 'ghost'}))
    assert err.get('Code') == 'NotFoundException', f'expected NotFoundException on mutation of deleted template, got {err!r}'
    assert err.get('HTTPStatusCode') == 404, f'expected HTTP 404 on mutation of deleted template, got {err!r}'
    expected_message = f"Template {name} does not exist."
    assert err.get('Message') == expected_message, f"expected the message {expected_message!r}, got {err.get('Message')!r}"
    err = _error(lambda: ses.test_render_email_template(TemplateName=name, TemplateData=json.dumps({'name': marker})))
    assert err.get('Code') == 'NotFoundException', f'expected NotFoundException rendering the deleted template, got {err!r}'
    assert err.get('HTTPStatusCode') == 404, f'expected HTTP 404 rendering the deleted template, got {err!r}'
    expected_message = f"Unable to find <{name}> for <{ctx.account}>"
    assert err.get('Message') == expected_message, f"expected the message {expected_message!r}, got {err.get('Message')!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict plus the response's HTTPStatusCode. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return {**err.response.get("Error", {}), "HTTPStatusCode": status}
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _template_names(ses):
    """Every email template name, following NextToken."""
    names, token = [], None
    while True:
        page = ses.list_email_templates(NextToken=token) if token else ses.list_email_templates()
        names.extend(t.get("TemplateName") for t in page.get("TemplatesMetadata", []))
        token = page.get("NextToken")
        if not token:
            return names


def _ignore_not_found(fn):
    """Teardown helper: a resource the check already deleted reads as not-found."""
    try:
        fn()
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
