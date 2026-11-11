"""cfn-validate-sfn-lambda-sqs-stack."""

from __future__ import annotations

from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-validate-sfn-lambda-sqs-stack"
GROUP = "deployment-order"
SERVICES = ["lambda", "stepfunctions", "sqs"]

DEPLOYMENTS = Path(__file__).parent / "deployments"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidateTemplate on the SFN, Lambda and SQS template reports CAPABILITY_NAMED_IAM and no
    parameters, and rejects the template with a dangling resource reference with ValidationError
    (exact message)."""
    template_path = DEPLOYMENTS / "sfn-lambda-sqs.yaml"
    assert template_path.is_file(), (
        f"deployment artifact missing on disk: {template_path}"
    )
    template = template_path.read_text()

    cfn = ctx.client("cloudformation")

    # Positive control: the template declares two named IAM::Role resources
    # (LambdaRole, SfnRole with explicit RoleName), so a target that actually
    # parses resource properties -- not just accepts arbitrary YAML -- must
    # report back that CAPABILITY_NAMED_IAM is required.
    resp = cfn.validate_template(TemplateBody=template)
    capabilities = resp.get("Capabilities", [])
    assert "CAPABILITY_NAMED_IAM" in capabilities, (
        f"expected CAPABILITY_NAMED_IAM for template with named IAM roles, got {capabilities}"
    )
    assert resp.get("Parameters", []) == [], (
        f"template declares no Parameters, but validate_template reported {resp.get('Parameters')}"
    )

    # Negative (always-invalid-input, no restore beat by construction): break exactly
    # one cross-resource reference -- FunctionArn now points at a logical id that does
    # not exist in the template -- and require the specific ValidationError. A target
    # that accepts any YAML blob (the ~40-line stub this check exists to reject) would
    # pass the positive control above and then wrongly accept this too.
    broken_template = template.replace(
        "FunctionArn:\n    Value: !GetAtt ProcessorFn.Arn",
        "FunctionArn:\n    Value: !GetAtt GhostFn.Arn",
    )
    assert broken_template != template, (
        "expected replacement to change the template text"
    )
    try:
        cfn.validate_template(TemplateBody=broken_template)
        raise AssertionError(
            "validate_template accepted a template with an unresolved GetAtt reference "
            "(Outputs.FunctionArn -> GhostFn, which is not declared in Resources)"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        assert code == "ValidationError", (
            f"expected ValidationError, got {code}: {message}"
        )
        expected = "Template error: instance of Fn::GetAtt references undefined resource GhostFn"
        assert message == expected, (
            f"expected the exact unresolved-reference message {expected!r}, got: {message!r}"
        )

    # Restore control: the identical original call still succeeds after the negative,
    # proving the rejection above was specific to the broken reference, not account state.
    resp2 = cfn.validate_template(TemplateBody=template)
    assert resp2.get("Capabilities", []) == capabilities, (
        f"identical valid template now reports different capabilities: {resp2.get('Capabilities')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
