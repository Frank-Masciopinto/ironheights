def charge():
    key = os.environ.get(
        "BILLING_API_KEY",
        "sk_FAKEbillingKeyNotReal0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdXYZ",
    )
    return key
