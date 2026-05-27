import re
import time

from threatpipe.dashboard import render_dashboard
from threatpipe.version import __version__


def test_dashboard_html_contains_version():
    html = render_dashboard()
    assert f"v{__version__}" in html


def test_dashboard_nonce_is_unique_per_render():
    a = render_dashboard()
    b = render_dashboard()
    extract = lambda h: re.findall(r'nonce="([^"]+)"', h)
    nonces_a = set(extract(a))
    nonces_b = set(extract(b))
    assert nonces_a
    assert nonces_a != nonces_b


def test_dashboard_includes_all_tabs():
    html = render_dashboard()
    for tab in ["overview", "incidents", "detections", "graph", "hunt", "attck", "response"]:
        assert f'data-view="{tab}"' in html


def test_dashboard_loads_cytoscape_cdn():
    html = render_dashboard()
    assert "cytoscape" in html.lower()
