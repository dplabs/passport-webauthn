const AuthenticatorData = require("./fido2/authenticatordata");
const utils = require("./utils");
const base64url = require("base64url");
const crypto = require("crypto");
const cose2jwk = require("cose-to-jwk");
const jwk2pem = require("jwk-to-pem");
const Attestation = require("./fido2/attestation");

// Constants for authenticator data flags.
var USER_PRESENT = 0x01;
var USER_VERIFIED = 0x04;

function validateCredentialsGet(self, req, ctx) {
  // https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion

  var response = req.body.response;
  var clientDataJSON = base64url.decode(response.clientDataJSON);

  // TODO: Verify that credentials was in allowedCredentials, if set

  var userHandle = null;
  if (response.userHandle) {
    userHandle = base64url.toBuffer(response.userHandle);
  }

  if (!ctx.user) {
    // If the user was not identified before the authentication ceremony was
    // initiated, response.userHandle must be present.
    //
    // NOTE: User handle being set should imply resident keys (???)
    if (!userHandle) {
      return self.fail({ message: "User handle not set" }, 403);
    }
  } else {
    if (userHandle && Buffer.compare(ctx.user.id, userHandle) != 0) {
      // If the user was identified before the authentication ceremony was
      // initiated, if response.userHandle is present, it must map to the
      // same user.
      return self.fail({ message: "User handle does not map to user" }, 403);
    }
  }

  var b_authenticatorData = base64url.toBuffer(response.authenticatorData);
  var authenticatorData = AuthenticatorData.parse(b_authenticatorData);

  // TODO: Support appID extension for rpIdHash

  // Verify that the RP ID hash contained in authenticator data matches the
  // hash of this app's (which is the relying party) RP ID.
  if (!utils.checkRPIDHash(req, authenticatorData.rpIdHash)) {
    return self.fail({ message: "RP ID hash mismatch" }, 403);
  }

  // Verify that the user present bit is set in authenticator data flags.
  if (!(authenticatorData.flags & USER_PRESENT)) {
    return self.fail({ message: "User not present" }, 403);
  }

  // TODO: Verify that extensions are as expected.

  var id = req.body.id;
  var flags = {
    userPresent: !!(authenticatorData.flags & USER_PRESENT),
    userVerified: !!(authenticatorData.flags & USER_VERIFIED),
  };

  const done = (err, user, publicKey, info) => {
    utils.verificationDone(self, err, user, publicKey, info, {
      clientDataJSON,
      b_authenticatorData,
      authenticatorData,
      response,
      id,
    });
  };

  try {
    if (self._passReqToCallback) {
      var arity = self._verify.length;
      switch (arity) {
        case 5:
          return self._verify(req, id, userHandle, flags, done);
        default:
          return self._verify(req, id, userHandle, done);
      }
    } else {
      var arity = self._verify.length;
      switch (arity) {
        case 4:
          return self._verify(id, userHandle, flags, done);
        default:
          return self._verify(id, userHandle, done);
      }
    }
  } catch (ex) {
    return self.error(ex);
  }
}
exports.validateCredentialsGet = validateCredentialsGet;

function validateCredentialsCreate(self, req, ctx) {
  // https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential

  var response = req.body.response;
  var clientDataJSON = base64url.decode(response.clientDataJSON);

  var b_attestation = base64url.toBuffer(response.attestationObject);
  var attestation = Attestation.parse(b_attestation);
  var authenticatorData = AuthenticatorData.parse(
    attestation.authData,
    true,
    false,
  );

  // Verify that the RP ID hash contained in authenticator data matches the
  // hash of this app's (which is the relying party) RP ID.
  if (!utils.checkRPIDHash(req, authenticatorData.rpIdHash)) {
    return self.fail({ message: "RP ID hash mismatch" }, 403);
  }

  // Verify that the user present bit is set in authenticator data flags.
  if (!(authenticatorData.flags & USER_PRESENT)) {
    return self.fail({ message: "User not present" }, 403);
  }

  // TODO: Verify alg is allowed

  // TODO: Verify that extensions are as expected.

  var format = self._attestationFormats[attestation.fmt];
  if (!format) {
    return self.fail(
      { message: "Unsupported attestation format: " + attestation.fmt },
      400,
    );
  }

  // Verify that the attestation statement conveys a valid attestation signature.
  var hash = crypto.createHash("sha256").update(clientDataJSON).digest();
  var vAttestation;
  try {
    vAttestation = format.verify(
      attestation.attStmt,
      attestation.authData,
      hash,
    );
  } catch (ex) {
    return self.fail({ message: ex.message }, 400);
  }

  var credentialId = base64url.encode(
    authenticatorData.attestedCredentialData.credentialId,
  );
  var jwk = cose2jwk(
    authenticatorData.attestedCredentialData.credentialPublicKey,
  );
  var pem = jwk2pem(jwk);
  var flags = {
    userPresent: !!(authenticatorData.flags & USER_PRESENT),
    userVerified: !!(authenticatorData.flags & USER_VERIFIED),
  };

  const done = (err, user, info) => {
    return utils.registrationDone(self, err, user, info);
  };

  try {
    if (self._passReqToCallback) {
      // TODO
      //self._verify(req, username, password, verified);
    } else {
      var arity = self._register.length;
      switch (arity) {
        case 8:
          return self._register(
            ctx.user,
            credentialId,
            pem,
            flags,
            authenticatorData.signCount,
            response.transports,
            vAttestation,
            done,
          );
        case 7:
          return self._register(
            ctx.user,
            credentialId,
            pem,
            flags,
            authenticatorData.signCount,
            response.transports,
            done,
          );
        case 6:
          return self._register(
            ctx.user,
            credentialId,
            pem,
            flags,
            authenticatorData.signCount,
            done,
          );
        case 5:
          return self._register(ctx.user, credentialId, pem, flags, done);
        default:
          return self._register(ctx.user, credentialId, pem, done);
      }
    }
  } catch (ex) {
    return self.error(ex);
  }
}
exports.validateCredentialsCreate = validateCredentialsCreate;
