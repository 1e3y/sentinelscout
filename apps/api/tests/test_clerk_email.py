from app.services.clerk import primary_email_info


def test_primary_email_requires_explicit_verified_status():
    data = {
        "primary_email_address_id": "idn_1",
        "email_addresses": [
            {
                "id": "idn_1",
                "email_address": "alice@example.com",
                "verification": {"status": "verified"},
            }
        ],
    }
    assert primary_email_info(data) == ("alice@example.com", True)

    unverified = {
        "primary_email_address_id": "idn_1",
        "email_addresses": [
            {
                "id": "idn_1",
                "email_address": "alice@example.com",
                "verification": {"status": "unverified"},
            }
        ],
    }
    assert primary_email_info(unverified) == ("alice@example.com", False)

    missing = {
        "primary_email_address_id": "idn_1",
        "email_addresses": [{"id": "idn_1", "email_address": "alice@example.com"}],
    }
    assert primary_email_info(missing) == ("alice@example.com", False)
