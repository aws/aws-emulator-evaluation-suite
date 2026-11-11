"""template-render-conditional-semantics."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "template-render-conditional-semantics"
GROUP = 'template'
SERVICES = ['sesv2']

@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestRenderEmailTemplate evaluates handlebars sections, not just scalar substitution."""
    ses = ctx.client('sesv2')
    name = ctx.unique_name('sim2real-behav-tmpl-cond-')
    ses.create_email_template(TemplateName=name, TemplateContent={'Subject': 'Hello {{name}}', 'Text': '{{#if premium}}PREMIUMTIER{{else}}BASICTIER{{/if}}|{{#each items}}[{{this}}]{{/each}}'})
    ctx.on_cleanup(lambda _k=name: ses.delete_email_template(TemplateName=_k))
    rendered_premium = ses.test_render_email_template(TemplateName=name, TemplateData='{"name":"Dana","premium":true,"items":["a","b"]}')['RenderedTemplate']
    assert 'PREMIUMTIER' in rendered_premium, rendered_premium
    assert 'BASICTIER' not in rendered_premium, rendered_premium
    assert '[a][b]' in rendered_premium, rendered_premium
    assert 'Dana' in rendered_premium, rendered_premium
    rendered_basic = ses.test_render_email_template(TemplateName=name, TemplateData='{"name":"Dana","premium":false,"items":[]}')['RenderedTemplate']
    assert 'BASICTIER' in rendered_basic, rendered_basic
    assert 'PREMIUMTIER' not in rendered_basic, rendered_basic
    assert '[a]' not in rendered_basic, rendered_basic
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
