"""op-contract-estimateTemplateCost."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from behavioral_harness import tags

CHECK = "op-contract-estimateTemplateCost"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})

# The URL's host label and path are fixed; the id is a fresh 40-char lowercase hex token
# per call, so the fragment is matched exactly rather than by substring.
_FRAGMENT_RE = re.compile(r"/estimate\?id=cloudformation/[0-9a-f]{40}")


def _assert_estimate_url(url):
    """The estimate URL is ``https://calculator.<domain>/#/estimate?id=cloudformation/<40 hex>``.
    The domain is the target's own, so the calculator label leads the host and the path and
    fragment are matched exactly."""
    parts = urlsplit(url) if isinstance(url, str) else None
    labels = (parts.hostname or "").split(".") if parts else []
    assert (parts is not None and parts.scheme == "https" and labels[0] == "calculator"
            and len(labels) > 1 and all(labels[1:]) and parts.path == "/" and not parts.query
            and _FRAGMENT_RE.fullmatch(parts.fragment)), (
        f"expected https://calculator.<domain>/#/estimate?id=cloudformation/<40 lowercase hex>, "
        f"got {url!r}"
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EstimateTemplateCost returns a pricing-calculator cost-estimate URL for a
    valid template; a syntactically invalid template body is rejected with
    ValidationError."""
    cfn = ctx.client("cloudformation")

    resp = cfn.estimate_template_cost(TemplateBody=_BUCKET_TEMPLATE)
    url = resp["Url"]
    _assert_estimate_url(url)

    code, message = _error(
        lambda: cfn.estimate_template_cost(TemplateBody="{ this is neither json nor yaml @@@")
    )
    assert code == "ValidationError", f"expected ValidationError for malformed template, got {code}"
    assert message == "Template format error: YAML not well-formed. (line 1, column 36)", (
        f"unexpected ValidationError message {message!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
