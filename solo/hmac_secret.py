# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#
# isort:skip_file


import binascii
import hashlib
import secrets

import fido2.cose
from fido2.extensions import HmacSecretExtension
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialParameters, PublicKeyCredentialDescriptor,
    PublicKeyCredentialType, PublicKeyCredentialRpEntity,
)

import solo.client


def make_credential(
    host="solokeys.dev",
    user_id="they",
    serial=None,
    pin=None,
    prompt="Touch your authenticator to generate a credential...",
    output=True,
    udp=False,
    algs=None
):
    if algs is None:
        algs = [fido2.cose.EdDSA.ALGORITHM, fido2.cose.ES256.ALGORITHM]

    user_id = user_id.encode()
    client = solo.client.find(solo_serial=serial, udp=udp).client

    rp = PublicKeyCredentialRpEntity(host, "Example RP")
    client.host = host
    client.origin = f"https://{client.host}"
    client.user_id = user_id
    user = fido2.webauthn.PublicKeyCredentialUserEntity(user_id, "A. User")
    challenge = secrets.token_bytes(32)

    if prompt:
        print(prompt)

    hmac_ext = HmacSecretExtension(client.ctap2)

    options = PublicKeyCredentialCreationOptions(
        rp,
        user,
        challenge,
        [PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, alg)
         for alg in algs],
        extensions=hmac_ext.create_dict(),
    )

    attestation_object, client_data = client.make_credential(options, pin=pin)

    credential = attestation_object.auth_data.credential_data
    credential_id = credential.credential_id
    if output:
        print(credential_id.hex())

    return credential_id, credential.public_key


def simple_secret(
    credential_id,
    secret_input,
    host="solokeys.dev",
    user_id="they",
    serial=None,
    pin=None,
    prompt="Touch your authenticator to generate a response...",
    output=True,
    udp=False,
):
    user_id = user_id.encode()

    client = solo.client.find(solo_serial=serial, udp=udp).client
    hmac_ext = HmacSecretExtension(client.ctap2)

    # rp = {"id": host, "name": "Example RP"}
    client.host = host
    client.origin = f"https://{client.host}"
    client.user_id = user_id
    # user = {"id": user_id, "name": "A. User"}
    credential_id = binascii.a2b_hex(credential_id)

    allow_list = [PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credential_id)]

    challenge = secrets.token_bytes(32)

    h = hashlib.sha256()
    h.update(secret_input.encode())
    salt = h.digest()

    if prompt:
        print(prompt)

    options = PublicKeyCredentialRequestOptions(
        challenge, 30000, host, allow_list, extensions=hmac_ext.get_dict(salt)
    )
    assertions, client_data = client.get_assertion(options, pin=pin)

    assertion = assertions[0]  # Only one cred in allowList, only one response.
    response = hmac_ext.results_for(assertion.auth_data)[0]
    if output:
        print(response.hex())

    return response
