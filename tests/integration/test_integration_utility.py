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