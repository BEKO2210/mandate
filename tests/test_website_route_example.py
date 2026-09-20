"""Website Route snippet must match the real constructor."""

from mandate.routes import Route


def test_website_route_example_constructs():
    route = Route(
        audience="mandate://procurement",
        base_url="https://api.example.com",
        allowed_methods=("POST",),
        allowed_paths=("/orders",),
        network_policy="public",
    )
    assert route.audience == "mandate://procurement"
    assert route.allowed_methods == ("POST",)
    assert route.allowed_paths == ("/orders",)
    assert route.network_policy == "public"
