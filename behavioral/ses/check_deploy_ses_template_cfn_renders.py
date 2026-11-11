"""deploy-ses-template-cfn-renders."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "deploy-ses-template-cfn-renders"
GROUP = "deploy"
SERVICES = ["ses"]

_TEMPLATE_BODY = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  TemplateNameParam:
    Type: String
Resources:
  SesTemplate:
    Type: AWS::SES::Template
    Properties:
      Template:
        TemplateName: !Ref TemplateNameParam
        SubjectPart: "Welcome {{name}}"
        HtmlPart: "<h1>Hello {{name}}</h1><p>Thanks for joining, {{name}}.</p>"
        TextPart: "Hello {{name}}, thanks for joining."
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::SES::Template deployed via CloudFormation is not just recorded as
    CREATE_COMPLETE -- GetTemplate returns its real content and TestRenderTemplate
    actually substitutes the declared {{name}} variable into rendered MIME output."""
    ses = ctx.client("ses")
    template_name = ctx.unique_name("sim2real-ses-cfntpl-")
    _deploy_cfn(ctx, _TEMPLATE_BODY, {"TemplateNameParam": template_name})

    got = ses.get_template(TemplateName=template_name)["Template"]
    assert got["TemplateName"] == template_name, (
        f"expected GetTemplate to return the CFN-deployed template {template_name!r}, "
        f"got {got['TemplateName']!r}"
    )
    assert "{{name}}" in got["SubjectPart"], (
        "expected the unrendered SubjectPart to retain the {{name}} placeholder, got "
        f"{got['SubjectPart']!r}"
    )
    assert "{{name}}" in got["HtmlPart"], (
        "expected the unrendered HtmlPart to retain the {{name}} placeholder, got "
        f"{got['HtmlPart']!r}"
    )

    rendered = ses.test_render_template(
        TemplateName=template_name, TemplateData='{"name": "Ada"}'
    )["RenderedTemplate"]
    assert "Welcome Ada" in rendered, (
        "expected the CFN-deployed template's SubjectPart to render 'Welcome Ada', got: "
        f"{rendered!r}"
    )
    assert "Hello Ada" in rendered, (
        "expected the CFN-deployed template's HtmlPart to render 'Hello Ada', got: "
        f"{rendered!r}"
    )
    assert "{{name}}" not in rendered, (
        "expected the {{name}} placeholder to be substituted in rendered output, got: "
        f"{rendered!r}"
    )

    err = _error_code(
        lambda: ses.test_render_template(TemplateName=template_name, TemplateData="{}")
    )
    assert err == (
        "MissingRenderingAttribute",
        "Attribute 'name' is not present in the rendering data.",
    ), (
        "expected TestRenderTemplate to reject TemplateData missing the declared 'name' "
        f"variable with MissingRenderingAttribute, got {err!r}"
    )


def _deploy_cfn(ctx: Any, template_body: str, parameters: dict[str, str]) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ses-stack-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return stack_name


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected TestRenderTemplate to reject this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
