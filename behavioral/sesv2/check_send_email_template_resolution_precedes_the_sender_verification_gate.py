"""send-email-template-resolution-precedes-the-sender-verification-gate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

# SendEmail ordering with the sender held unverified:
#   - The FromEmailAddress identity gate runs BEFORE template-NAME resolution: a valid stored
#     template and a MISSING template name both return MessageRejected.
#   - Template-DATA validation runs BEFORE the identity gate and agrees with
#     TestRenderEmailTemplate: malformed TemplateData returns a code distinct from MessageRejected.
#   - The mailbox simulator recipient needs no verification and no production access; every leg
#     is refused before send, so nothing is delivered.

CHECK = "send-email-template-resolution-precedes-the-sender-verification-gate"
GROUP = "templates-v2"
SERVICES = ["sesv2"]

#: The mailbox simulator: the sanctioned recipient that needs no verification.
_SIMULATOR = "success@simulator.amazonses.com"
_GOOD_DATA = '{"name":"Ada"}'
#: Deliberately not JSON; TestRenderEmailTemplate's verdict on it is the expected SendEmail code.
_MALFORMED_DATA = '{"name": '


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEmail's sender-identity gate runs after template-DATA validation but before NAME lookup:
    with an unverified sender a missing template yields MessageRejected, while malformed
    TemplateData yields TestRenderEmailTemplate's own error code.
    """
    sesv2 = ctx.client("sesv2")
    template = _create_template(ctx)
    unverified = ctx.unique_name("sim2real-behav-unverified-") + "@example.com"
    missing_template = ctx.unique_name("sim2real-behav-absent-tmpl-")

    # Beat 1 — positive control. A real success: the stored template renders.
    rendered = sesv2.test_render_email_template(TemplateName=template, TemplateData=_GOOD_DATA)[
        "RenderedTemplate"
    ]
    assert "Ada" in rendered, (
        f"positive control failed: TestRenderEmailTemplate({template}) with {_GOOD_DATA} produced a "
        f"render that does not contain the substituted value 'Ada': {rendered[:200]!r}"
    )
    assert "{{name}}" not in rendered, (
        f"positive control failed: the {{{{name}}}} placeholder survived rendering: {rendered[:200]!r}"
    )

    # Beat 2 — the baseline refusal. Everything is valid except the sender, so this is the code the
    # identity gate produces.
    not_verified = (
        "MessageRejected",
        f"Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {unverified}",
    )
    good_template_error = _error(
        lambda: sesv2.send_email(
            FromEmailAddress=unverified,
            Destination={"ToAddresses": [_SIMULATOR]},
            Content={"Template": {"TemplateName": template, "TemplateData": _GOOD_DATA}},
        )
    )
    good_template_code = good_template_error[0]
    assert good_template_error == not_verified, (
        f"SendEmail with a valid stored template and an unverified sender returned "
        f"{good_template_code!r}, expected MessageRejected (the identity gate)"
    )

    # Beat 3 — break exactly one thing: the template name. AWS returns the SAME code as the valid
    # template, not NotFoundException: the identity gate fires before the template store is
    # consulted, so an unverified sender masks a missing template.
    missing_template_error = _error(
        lambda: sesv2.send_email(
            FromEmailAddress=unverified,
            Destination={"ToAddresses": [_SIMULATOR]},
            Content={"Template": {"TemplateName": missing_template, "TemplateData": _GOOD_DATA}},
        )
    )
    missing_template_code = missing_template_error[0]
    assert missing_template_code == good_template_code, (
        f"SendEmail naming a template that does not exist returned {missing_template_code!r} while "
        f"the identical call against the existing template {template} returned "
        f"{good_template_code!r}; with the sender unverified, the identity gate must mask a missing "
        f"template name the same way it masks a valid one"
    )
    assert missing_template_error == not_verified, (
        f"SendEmail naming a template that does not exist returned {missing_template_code!r} with "
        f"an unverified sender, expected MessageRejected: the identity gate runs before "
        f"template-name resolution, so a caller cannot learn their template is missing until their "
        f"sender is verified"
    )

    # Effect-absent via an independent read on a different operation.
    absent_code = _error(lambda: sesv2.get_email_template(TemplateName=missing_template))
    assert absent_code == ("NotFoundException", f"Template {missing_template} does not exist."), (
        f"GetEmailTemplate({missing_template}) returned {absent_code!r}, expected NotFoundException "
        f"— the template SendEmail refused must genuinely not exist"
    )

    # Beat 4 — break a different single thing: the template DATA. The expected code is read off
    # TestRenderEmailTemplate in this run (AWS: BadRequestException, never overridden by the gate).
    render_verdict = _error_code(
        lambda: sesv2.test_render_email_template(
            TemplateName=template, TemplateData=_MALFORMED_DATA
        )
    )
    send_verdict = _error_code(
        lambda: sesv2.send_email(
            FromEmailAddress=unverified,
            Destination={"ToAddresses": [_SIMULATOR]},
            Content={"Template": {"TemplateName": template, "TemplateData": _MALFORMED_DATA}},
        )
    )
    assert send_verdict == render_verdict, (
        f"TestRenderEmailTemplate rejected the template data with {render_verdict!r} but SendEmail "
        f"rejected the identical data on the identical template with {send_verdict!r}; the two "
        f"paths must apply one validation"
    )
    assert send_verdict != good_template_code, (
        f"SendEmail returned the same code {send_verdict!r} for malformed template data as for "
        f"valid data, so the template data is not being validated ahead of the identity gate"
    )

    # Beats 5 and 6 — restore: nothing was left broken, and the original call is unchanged.
    restored_code = _error_code(
        lambda: sesv2.send_email(
            FromEmailAddress=unverified,
            Destination={"ToAddresses": [_SIMULATOR]},
            Content={"Template": {"TemplateName": template, "TemplateData": _GOOD_DATA}},
        )
    )
    assert restored_code == good_template_code, (
        f"after the two broken variants, the original SendEmail returned {restored_code!r} instead "
        f"of the unchanged {good_template_code!r}"
    )
    # Not a byte-equality check against `rendered`: TestRenderEmailTemplate stamps a live `Date:`
    # header and a fresh random MIME boundary on every call, so two renders of the identical
    # template with identical data are never byte-identical even on a correct target. The stable,
    # meaningful invariant is the substitution itself.
    reread = sesv2.test_render_email_template(TemplateName=template, TemplateData=_GOOD_DATA)[
        "RenderedTemplate"
    ]
    assert "Ada" in reread, (
        f"the stored template no longer renders the substituted value after the refused sends: "
        f"{reread[:200]!r}"
    )
    assert "{{name}}" not in reread, (
        f"the {{{{name}}}} placeholder reappeared unsubstituted after the refused sends: "
        f"{reread[:200]!r}"
    )

    _assert_codes_partition(
        same={"valid-template": good_template_code, "missing-template": missing_template_code},
        different={"malformed-template-data": send_verdict},
    )


def _create_template(ctx) -> str:
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-stageorder-")
    sesv2.create_email_template(
        TemplateName=name,
        TemplateContent={
            "Subject": "Hello {{name}}",
            "Text": "Hi {{name}}, this is a sim2real behavioral probe.",
            "Html": "<p>Hi {{name}}</p>",
        },
        Tags=[{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sesv2.delete_email_template(TemplateName=name))
    return name


def _error_code(fn) -> str:
    """The ClientError code of fn(); raises on unexpected success like `_error`."""
    return _error(fn)[0]


def _error(fn) -> tuple[str, str]:
    """Returns the ClientError (Code, Message)."""
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        "the call succeeded where a refusal was required; an unverified sender or an absent "
        "template must never produce a 200"
    )


def _assert_codes_partition(same: dict[str, str], different: dict[str, str]) -> None:
    """Backstop: the valid- and missing-template legs share ONE code, while the malformed-data leg,
    resolved before the identity gate, lands on a different one."""
    same_codes = set(same.values())
    assert len(same_codes) == 1, (
        f"the valid-template and missing-template legs should agree while the sender is "
        f"unverified (the identity gate masks the template-name lookup either way), but got "
        f"{same!r}"
    )
    different_codes = set(different.values())
    assert not (same_codes & different_codes), (
        f"the malformed-template-data leg {different!r} should be resolved before the identity "
        f"gate and land on a different code than the masked legs {same!r}, but they collided"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
