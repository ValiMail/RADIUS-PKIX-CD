RADIUS-PKIX-CD
--------------

RADIUS and PKIX-CD proof-of-concept. 

Uses DANE PKIX-CD mode for safely enabling EAP-TLS across CAs and organizations, without changing the way that traditional PKI works.

This tool contains two scripts, ``pkix_cd_manage_trust`` and ``pkix_cd_verify``. The former is intended to be run as a scheduled job, 
and the latter acts as an authz mechanism for EAP-TLS in Freeradius 3.0. The Called-Station-ID is typically formatted MAC:SSID for WiFi connections.
The MAC address part is ignored by these tools, and they use the SSID in the process of determining which entities should be allowed network access.

----

:: 

    pkix_cd_manage_trust.py [-h] --infile INFILE --trustmap TRUSTMAP --cacerts CACERTS

    Manage trust map for radius_pkix_cd tool. Infile format is pipe delimited: 
        CalledStation|my._device.example.com 
    ...where CalledStation is the Called-Station-Id and my._device.example.com is the name of the device allowed to access the Called-Station-Id. Devices may be associated with multiple CalledStations.

    optional arguments:
      -h, --help                show this help message and exit
      --infile INFILE           Network access list.
      --trustmap TRUSTMAP       Trust map (outfile) for pkix_cd_verify.
      --cacerts CACERTS         Outfile for CA certificates.
      --ns_override NS          Override the default system nameserver.

----

::

    pkix_cd_verify.py [-h] --called CALLED --calling CALLING --certfile CERTFILE --trustmap TRUSTMAP [--live-verify] [--require-registry]

    Authorize supplicants against the access configuration, using PKIX-CD for identity to trust anchor mapping. 
    Exit codes: 
        1: Missing trust map. 
        2: Missing certificate file. 
        3: Invalid called-station-id 
        4: Live verify failed. 
        5: IoT Registry check failed.

    optional arguments:
      -h, --help           show this help message and exit
      --called CALLED      Called-Station-Id.
      --calling CALLING    Callling-Station-Id.
      --certfile CERTFILE  Certificate file presented by supplicant.
      --trustmap TRUSTMAP  Trust map, provided by pkix_cd_manage_trust.
      --live-verify        Verify directly against DNS, in addition to cached information.
      --require-registry   Set this to require IoT Registry revocation checks for all clients.
      --ns_override NS     Override the default system nameserver.

----

Together, these commands can be used to manage access for DNS-based identities implementing PKIX-CD (certificate usage mode 4).

The ``pkix_cd_verify`` command can be used in the Freeradius EAP-TLS config to prevent cross-domain identity signing.

``client = "/usr/local/bin/pkix_cd_verify --calling=%{User-Name} --called=%{Called-Station-Id} --certfile=%{TLS-Client-Cert-Filename} --trustmap=/etc/freeradius/trust_map.json"``

For more information in how it all woks, check out:

- .circleci/config.yml
- tests/configs/freeradius/3.0/eap-tls
- tests/configs/eapol_test/eapol_test.conf