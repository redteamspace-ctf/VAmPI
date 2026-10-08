register_user_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string", "minLength": 1, "maxLength": 128},
        "password": {"type": "string", "minLength": 1, "maxLength": 128},
        "email": {"type": "string", "minLength": 1, "maxLength": 128}
    },
    "required": ["username", "password", "email"],
    "additionalProperties": False
}

login_user_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "password": {"type": "string"}
    },
    "required": ["username", "password"]
}

update_email_schema = {
    "type": "object",
    "properties": {
        "email": {"type": "string"}
    },
    "required": ["email"]
}

add_book_schema = {
    "type": "object",
    "properties": {
        "book_title": {"type": "string"},
        "secret": {"type": "string"}
    },
    "required": ["book_title", "secret"]
}
