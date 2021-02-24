import os
import pprint

import radius_pkix_cd
from radius_pkix_cd.utility import Utility

here_dir = os.path.dirname(os.path.abspath(__file__))
fixtures_dir = os.path.join(here_dir, "../fixtures/")


class TestIntegrationUtility:
    """Integration tests for the Utility class."""

    def test_integration_utility_get_authz_config(self):
        infile = os.path.join(fixtures_dir, "trust_source.txt")
        trust_structure = Utility.get_authz_config(infile)
        expected = {"my._device.example.com": ["SSID1"],
                    "your._device.example.com": ["SSID1", "SSID2"]}
        pprint.pprint(trust_structure)
        pprint.pprint(expected)
        assert trust_structure == expected
        return

   