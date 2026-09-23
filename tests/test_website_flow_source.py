"""Landing-page flow animation must match the documented architecture."""

from pathlib import Path


def test_website_flow_models_direct_and_human_stepup_paths():
    script = Path("site/script.js").read_text(encoding="utf-8")
    html = Path("site/index.html").read_text(encoding="utf-8")

    assert "const directSequence = [0, 1, 2, 4, 5]" in script
    assert "const stepUpSequence = [0, 1, 2, 3, 4, 5]" in script
    assert '["2-4", [[280, 214], [470, 214]]]' in script
    assert '["3-4", [[280, 340], [470, 340], [470, 214]]]' in script

    # The packet is JS-controlled from one state machine; no independent SMIL loop.
    assert "<animateMotion" not in html

    # The optional human branch is visually distinct from the direct route.
    assert html.count('class="wire wire-optional"') == 2
    assert html.count('class="wire wire-main"') == 2

    # Denial is shown, not just success: it stops at the gate, never draws a
    # route to the upstream, and is still receipted.
    assert "const deniedSequence = [0, 1, 2]" in script
    assert 'id="stamp"' in html and 'id="cut"' in html
    assert "The denial is signed and chained like any receipt" in script
