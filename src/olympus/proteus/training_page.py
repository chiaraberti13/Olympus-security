"""Static training page shown to a simulated phishing "victim".

Proteus never collects real credentials: whoever "clicks" a simulated
campaign link lands on a static page that immediately discloses this was
a training exercise. No form, no input field, no submission target —
nothing here can ever capture a credential, by construction.
"""

from __future__ import annotations

TRAINING_PAGE_TITLE = "Security Awareness Training"


def render_training_page(campaign_name: str) -> str:
    """Render the static HTML training-disclosure page for ``campaign_name``.

    Contains no ``<form>`` or ``<input>`` element and requests nothing
    from the reader — it only discloses the exercise and points to
    awareness guidance.
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{TRAINING_PAGE_TITLE}</title>
</head>
<body>
<h1>{TRAINING_PAGE_TITLE}</h1>
<p>
  This was a simulated phishing exercise (campaign: <strong>{campaign_name}</strong>),
  run as part of Olympus Demo Corp's security awareness program.
</p>
<p>
  No credentials or personal data were collected. If this had been a real phishing
  email, your credentials could have been stolen. Please review your organization's
  phishing-awareness guidance and report suspicious emails going forward.
</p>
</body>
</html>
"""
