const AuthenticatorData = require("../authenticatordata");
const cbor = require("cbor");
const cose2jwk = require("cose-to-jwk");
const crypto = require("crypto");

exports.verify = function (attStmt, authData, hash) {
  const att = this.parse(attStmt);
  const data = Buffer.concat([authData, hash]);

  if (att.trustPath.length > 0) {
    const ok = crypto
      .createVerify("sha256")
      .update(data)
      .verify(att.trustPath[0].publicKey, att.signature);
    if (!ok) {
      return false;
    }

    // TODO: Verify id-fido-gen-ce-aaguid extension in attestation cert.
    // TODO: Verify that cert meets requirements

    return {
      type: undefined,
      format: "packed",
      trustPath: att.trustPath,
    };
  } else {
    const authenticatorData = AuthenticatorData.parse(authData, true, false);
    const cwk = cbor.decodeFirstSync(
      authenticatorData.attestedCredentialData.credentialPublicKey,
    );
    if (att.algorithm != cwk.get(3)) {
      throw new Error(
        "Packed attestation algorithm must match algorithm of credential public key",
      );
    }

    const jwk = cose2jwk(
      authenticatorData.attestedCredentialData.credentialPublicKey,
    );
    const key = crypto.createPublicKey({ key: jwk, format: "jwk" });
    const ok = crypto
      .createVerify("sha256")
      .update(data)
      .verify(key, att.signature);
    if (!ok) {
      return false;
    }
    return {
      type: "self",
      format: "packed",
      trustPath: att.trustPath,
    };
  }
};

exports.parse = function (attStmt) {
  const att = {
    algorithm: attStmt.alg,
    signature: attStmt.sig,
    trustPath: [],
  };
  if (attStmt.x5c) {
    attStmt.x5c.forEach(function (c) {
      const cert = new crypto.X509Certificate(c);
      att.trustPath.push(cert);
    });
  }
  return att;
};
