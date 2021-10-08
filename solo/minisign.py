from fido2.ctap2.extensions import Ctap2Extension


class MinisignExtension(Ctap2Extension):
    NAME = "minisign"
    HASH_LEN = 64

    def process_get_input(self, inputs):
        data = self.is_supported() and inputs.get("minisign")
        if not data:
            return

        digest, trusted_comment = data["hash"], data["trustedComment"]

        if type(digest) is not bytes or type(trusted_comment) is not bytes:
            raise ValueError("hash and trustedComment should be of type bytes")

        if len(digest) != self.HASH_LEN:
            raise ValueError("Invalid hash length")

        return {
            1: digest,
            2: trusted_comment
        }

    def process_get_output(self, auth_data):
        value: bytes = auth_data.extensions.get(self.NAME)
        return {"minisign": {"globalSignature": value}}
