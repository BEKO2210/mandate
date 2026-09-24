"""The demo on the landing page is the demo the code plays.

The page used to open with an animation of the architecture — a packet
moving between boxes, drawn by hand. It showed what Mandate is meant to do.
The terminal that replaced it shows what `mandate demo shop` did: the same
steps, labels and outcomes. A page about verifiable claims should not be
able to drift from the run it says it recorded, so this checks it.
"""

import re
from html import unescape
from pathlib import Path

from mandate.demo_shop.scenario import EXPECTED, STEPS


def test_website_demo_matches_the_shop_scenario():
    html = Path("site/index.html").read_text(encoding="utf-8")
    items = re.findall(r'<li data-outcome="([A-Z_]+)"[^>]*>.*?<b>(.*?)</b>', html, re.S)
    assert len(items) == len(STEPS), "the page shows every step of the scenario, no more"

    for (outcome, label), (step_label, tool, _), expected in zip(items, STEPS, EXPECTED):
        label = unescape(label)
        assert outcome == expected, (label, outcome, expected)
        if tool is None:
            assert label.startswith("the human approves rcpt_"), label
        else:
            assert label == step_label, (label, step_label)

    scenario = Path("mandate/demo_shop/scenario.py").read_text(encoding="utf-8")
    grant = re.search(r'<p class="demo-grant">(.*?)</p>', html).group(1)
    assert grant in scenario, "the grant line is the one the demo prints"
    assert "Orders placed: 2 (290 EUR)" in html

    # The architecture animation is gone, and nothing replaced it with a loop
    # that could show something the code does not do.
    assert "<animateMotion" not in html and "stageboard" not in html
