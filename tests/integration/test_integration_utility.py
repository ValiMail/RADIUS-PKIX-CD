import os
import pprint

from unittest.mock import MagicMock

from radius_pkix_cd.utility import Utility
from dane_discovery.pki import PKI
from dane_discovery.dane import DANE

here_dir = os.path.dirname(os.path.abspath(__file__))
fixtures_dir = os.path.join(here_dir, "../fixtures/")

private_cert_name = "ecc.air-quality-sensor._device.example.net.cert.pem"
private_cert_path = os.path.join("tests/ca2/", private_cert_name)
registry_cert_name = "iotreg.ca.cert.pem"
registry_cert_path = os.path.join("tests/ca2/", registry_cert_name)

"""Registry-issued certificate contents:
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1b:8d:8f:3f:f9:11:30:5b:f3:f0:3b:6e:b1:df:62:b0:c6:1e:a5:97
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=IoT Registry TEST CA
        Validity
            Not Before: Oct  4 23:37:49 2021 GMT
            Not After : Dec 31 23:59:59 9999 GMT
        Subject: CN=8912230200031010271F.iotregistry.ca
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    04:4b:59:2d:78:3a:93:b4:50:e9:52:0d:94:5e:11:
                    c1:30:19:13:72:e9:a6:4d:be:49:c7:31:42:d4:f7:
                    a1:e3:c3:74:49:12:fa:c9:10:3d:44:7f:03:0e:1b:
                    80:86:4a:84:3e:39:2b:55:8b:ff:3f:79:a6:3f:ae:
                    d8:ba:72:ce:d9
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Authority Key Identifier: 
                keyid:D8:8F:35:60:28:CF:FD:37:73:39:E1:70:E2:04:8A:AD:96:77:F1:00

            X509v3 Subject Key Identifier: 
                DE:47:96:E0:3E:ED:35:79:67:51:4A:D2:C3:36:3B:A0:97:75:4E:1C
            X509v3 Subject Alternative Name: 
                DNS:8912230200031010271F._device.universalauth.com, DNS:8912230200031010271F._device.telus.com
    Signature Algorithm: ecdsa-with-SHA256
         30:44:02:20:56:fb:ce:a6:8f:14:e8:46:bd:41:09:3a:69:6c:
         ce:36:c9:5e:df:0b:73:64:ba:fb:0a:6c:ea:8b:59:32:ec:9d:
         02:20:0a:78:90:16:74:20:c2:b6:a7:3e:87:24:10:62:1b:d9:
         8a:63:ae:86:78:05:3b:27:b2:d3:03:93:5c:84:1d:e8

"""

class TestIntegrationUtility:
    """Integration tests for the Utility class."""

    def get_file_contents(self, file_path):
        """Return the contents of a file."""
        with open(file_path) as f_p:
            return f_p.read()

    def generate_response(self, msgs):
        """Return an rrset for testing."""
        response = {"dnssec": False, "tcp": True, "tls": False,
                    "responses": msgs}
        return response

    def test_integration_utility_get_authz_config(self):
        infile = os.path.join(fixtures_dir, "trust_source.txt")
        trust_structure = Utility.get_authz_config(infile)
        expected = {"my._device.example.com": ["SSID1"],
                    "your._device.example.com": ["SSID1", "SSID2"]}
        pprint.pprint(trust_structure)
        pprint.pprint(expected)
        assert trust_structure == expected
        return

    def test_integration_check_iot_registry_issuance(self):
        """Test the utility function which identifies IoT Registry issuance."""
        private_cert_pem = self.get_file_contents(private_cert_path)
        registry_cert_pem = self.get_file_contents(registry_cert_path)
        assert Utility.check_iot_registry_issuance(registry_cert_pem)
        assert not Utility.check_iot_registry_issuance(private_cert_pem)

    def test_integration_check_iot_registry_revoked(self):
        """Test the utility function which identifies IoT Registry issuance."""
        tlsa_record_fmt = "{}. 373 IN TLSA {}"
        registry_cert_pem = self.get_file_contents(registry_cert_path)
        non_registry_cert_pem = self.get_file_contents(private_cert_path)
        test_dns_name = PKI.get_cert_meta(registry_cert_pem)["subject"]["commonName"]
        mock_dane = DANE
        
        tlsa_record_good = tlsa_record_fmt.format(test_dns_name, DANE.generate_tlsa_record(3, 0, 1, registry_cert_pem))
        tlsa_record_bad_1 = tlsa_record_fmt.format(test_dns_name, DANE.generate_tlsa_record(3, 0, 1, registry_cert_pem))
        tlsa_record_bad_2 = tlsa_record_fmt.format(test_dns_name, DANE.generate_tlsa_record(3, 1, 1, registry_cert_pem))
        
        response = self.generate_response([tlsa_record_good])
        print(response)
        mock_dane.get_responses = MagicMock(return_value=response)
        result = DANE.get_tlsa_records(test_dns_name)
        # Pass
        assert not Utility.check_iot_registry_revoked(registry_cert_pem, None)
        
        # Fail, hash does not match.
        response = self.generate_response([tlsa_record_bad_1])
        print(response)
        mock_dane.get_responses = MagicMock(return_value=response)
        assert Utility.check_iot_registry_revoked(non_registry_cert_pem, None)
        
        # Fail, bad TLSA record config.
        response = self.generate_response([tlsa_record_bad_2])
        print(response)
        mock_dane.get_responses = MagicMock(return_value=response)
        assert Utility.check_iot_registry_revoked(non_registry_cert_pem, None)