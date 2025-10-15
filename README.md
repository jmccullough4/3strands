## 3 Strands Cattle Co. Dashboard

### Google Workspace single sign-on (SAML)

The dashboard now relies on Google Workspace SAML sign-in. Install the optional dependency and provide the IdP settings with an `instance/config.py` file:

```bash
pip install python3-saml
```

```python
# instance/config.py
EXTERNAL_BASE_URL = "http://dashboard.3strands.co:8081"
SAML_IDP_ENTITY_ID = "https://accounts.google.com/o/saml2?idpid=C040clheo"
SAML_IDP_SSO_URL = "https://accounts.google.com/o/saml2/idp?idpid=C040clheo"
SAML_IDP_X509CERT = """MIIDdDCCAlygAwIBAgIGAZnp2SLbMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJbmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dvb2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMjUxMDE1MjE0OTA1WhcNMzAxMDE0MjE0OTA1WjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx0zhfINES7iJ0gnEsKfSikxNwfQ6ltqFlcX8CPFrDnLORh1aP+un05Djx513Qhkqss+CwJJYH+HYmdHOhoy3HsFMUt6Hj06C/v2dFLzIrhuY9ASzyr75TzAWUztTFWOwtyde1cfQlT+3obzJp1bQcWd7ok0HCOjRProbX61hSDM/uMGuqDUIUSisctqP40NKYEn3XAu9k98C7dQIJEnlFBSR/OpNUIUAv1ORvjf+fRIlsXIo/TUndmyfp9oul1VvKWGh1F2A1+Ih3jQGTGxUAlNAUT4MnM2/Ew+gEPummJE4u6GSzqijUT1+3ZJKCEdSn4cnriq9N+z7zebj4aSjBwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCosOuC9TX2XqwrPepEzZEiGlE/kgq7feBOmefyj0voomj5VxKVyKWKtk0E/qd2ReN7eDZjrTKAuJof9YFcJqS7SeSl/XAW+KwhBvzdX8DN9T+A2Syg/p8tmSB64GWPF4HriHn6gp/5SnYaAfeX7amADBTzmRbDd6cX8HRryK3Zt+VCGk05vbq+noHVV3WkY7Kxl1+MRMfCBZv3o5Sr3JvlhfVfFd0ccRtvpAepSsC9lkICDiCxde3tkfG28byooNDYX3eyVy0Q1Ujg/yv/+OarchN058SLsXk3H9Zg/2FjEpe26qZu0jKTEPFK95/VYI4LCZ4gkVj/VDJG7RDHD8Cu"""
# Optional: override the default metadata URL for the service provider
SAML_SP_ENTITY_ID = ""
```

Only the addresses that the admin authorizes inside the Access Control panel can sign in. Other Google accounts will complete the SAML handshake but won't gain access to the dashboard.

> **Note:** Google blocks SAML callbacks that resolve to private IP addresses. For production deployments, secure the dashboard behind a public hostname (HTTP or HTTPS) that you configure in `EXTERNAL_BASE_URL` and register in the Google Admin console as a trusted ACS location.
