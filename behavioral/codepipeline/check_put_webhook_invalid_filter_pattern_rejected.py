"""put-webhook-invalid-filter-pattern-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-webhook-invalid-filter-pattern-rejected"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _webhook_names(cp):
    out = []
    for page in cp.get_paginator("list_webhooks").paginate():
        out.extend(w["definition"]["name"] for w in page.get("webhooks", []))
    return out


def _definition(name, target_pipeline, *, filters, authentication="UNAUTHENTICATED",
                auth_config=None):
    return {
        "name": name,
        "targetPipeline": target_pipeline,
        "targetAction": "SourceAction",
        "authentication": authentication,
        "authenticationConfiguration": {} if auth_config is None else auth_config,
        "filters": filters,
    }


def _reject(cp, definition):
    """Call put_webhook; return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING a definition real AWS refuses is the strongest signal available."""
    try:
        resp = cp.put_webhook(webhook=definition)
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects webhook {definition['name']!r}, but it SUCCEEDED: {resp!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutWebhook rejects an unparseable filter jsonPath with InvalidWebhookFilterPatternException and
    GITHUB_HMAC without a secret with InvalidWebhookAuthenticationParametersException, each with its exact
    message; only the valid webhook is listed.
    """
    cp = ctx.client("codepipeline")
    # PutWebhook performs no target-pipeline existence check, so no pipeline needs to exist here.
    target = ctx.unique_name("sim2real-behav-absent-pipeline-")
    timeout_s = 60

    # Control first: a well-formed filter is accepted and the webhook is listed.
    good = ctx.unique_name("sim2real-behav-whok-")
    resp = cp.put_webhook(webhook=_definition(
        good, target, filters=[{"jsonPath": "$.ref", "matchEquals": "refs/heads/main"}]
    ), tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_webhook(name=good))
    assert resp["webhook"]["definition"]["filters"] == [
        {"jsonPath": "$.ref", "matchEquals": "refs/heads/main"}
    ], f"control webhook did not round-trip its filter: {resp['webhook']['definition']!r}"
    listed = _poll(lambda: _webhook_names(cp), lambda ns: good in ns,
                   timeout_s=timeout_s, interval_s=2)
    assert good in listed, f"accepted webhook {good} is absent from ListWebhooks"

    # Break exactly one thing: the jsonPath expression is unparseable.
    bad_filter = ctx.unique_name("sim2real-behav-whbad-")
    bad_json_path = "$.[[not-a-json-path"
    error = _reject(cp, _definition(
        bad_filter, target,
        filters=[{"jsonPath": bad_json_path, "matchEquals": "refs/heads/main"}],
    ))
    assert error.get("Code") == "InvalidWebhookFilterPatternException", (
        f"PutWebhook accepted (or misclassified) an unparseable jsonPath: error was "
        f"{error!r}, expected InvalidWebhookFilterPatternException"
    )
    expected_message = f"Request contains invalid filter pattern: {bad_json_path}"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # A second, independent single-field mutation: GITHUB_HMAC with no secret token.
    bad_auth = ctx.unique_name("sim2real-behav-whauth-")
    error = _reject(cp, _definition(
        bad_auth, target,
        filters=[{"jsonPath": "$.ref", "matchEquals": "refs/heads/main"}],
        authentication="GITHUB_HMAC", auth_config={},
    ))
    assert error.get("Code") == "InvalidWebhookAuthenticationParametersException", (
        f"PutWebhook accepted (or misclassified) GITHUB_HMAC with an empty "
        f"authenticationConfiguration: error was {error!r}, expected "
        f"InvalidWebhookAuthenticationParametersException"
    )
    expected_message = "Optional['authenticationConfig' should contain only one property: 'SecretToken']"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent for both rejections; the control webhook is undisturbed.
    names = _poll(
        lambda: _webhook_names(cp),
        lambda ns: bad_filter not in ns and bad_auth not in ns,
        timeout_s=timeout_s, interval_s=2,
    )
    assert bad_filter not in names, f"rejected webhook {bad_filter} is present in ListWebhooks"
    assert bad_auth not in names, f"rejected webhook {bad_auth} is present in ListWebhooks"
    assert good in names, f"control webhook {good} disappeared after the rejections"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
