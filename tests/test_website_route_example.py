"""Website Route snippet must match the real constructor."""

from mandate.routes import Operation, Route


def test_website_route_example_constructs():
    route = Route(
        audience="mandate://procurement",
        base_url="https://api.example.com",
        allowed_methods=("POST",),
        allowed_paths=("/orders",),
        network_policy="public",
        operations=(
            Operation(
                action="purchase.office",
                method="POST",
                path="/orders",
                fields=("action", "amount_minor", "currency", "execution_id"),
                context_fields=("sku",),
            ),
        ),
    )
    assert route.audience == "mandate://procurement"
    assert route.allowed_methods == ("POST",)
    assert route.allowed_paths == ("/orders",)
    assert route.network_policy == "public"
    op = route.operation_for("purchase.office")
    assert (op.method, op.path) == ("POST", "/orders")
    assert route.operation_for("purchase.it") is None
