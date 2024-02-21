const passport = require("passport-strategy");
const base64url = require("base64url");
const util = require("util");
const utils = require("./utils");
const SessionStore = require("./store/session");
const operations = require("./strategy-operations");

/**
 * Create a new `Strategy` object.
 */
function Strategy(options, verify, verifySignCount, register) {
  if (typeof options == "function") {
    register = verifySignCount;
    verifySignCount = verify;
    verify = options;
    options = {};
  }
  if (typeof register == "undefined") {
    register = verifySignCount;
    verifySignCount = undefined;
  }

  passport.Strategy.call(this);
  this.name = "webauthn";
  this._attestationFormats =
    options.attestationFormats || require("./fido2/formats");
  this._verify = verify;
  this._verifySignCount = verifySignCount;
  this._register = register;
  this._store = options.store || new SessionStore();
}

// Inherit from `passport.Strategy`.
util.inherits(Strategy, passport.Strategy);

function validated(self, req, err, ok, ctx, clientData) {
  if (err) {
    return self.error(err);
  }
  if (!ok) {
    return self.fail(ctx, 403);
  }
  ctx = ctx || {};

  // Verify that the origin contained in client data matches the origin of this
  // app (which is the relying party).
  var origin = utils.origin(req);
  if (origin !== clientData.origin) {
    return self.fail({ message: "Origin mismatch" }, 403);
  }

  // TODO: Verify the state of Token Binding for the TLS connection over which
  // the attestation was obtained.

  if (clientData.type === "webauthn.get") {
    return operations.validateCredentialsGet(self, req, ctx);
  } else if (clientData.type === "webauthn.create") {
    return operations.validateCredentialsCreate(self, req, ctx);
  } else {
    return self.fail(
      { message: "Unsupported response type: " + clientData.type },
      400,
    );
  }
}

Strategy.prototype.authenticate = function (req, options) {
  var self = this;

  var response = req.body.response;
  var clientDataJSON = base64url.decode(response.clientDataJSON);
  var clientData = JSON.parse(clientDataJSON);

  var challenge = base64url.toBuffer(clientData.challenge);

  // Verify that the challenge (aka nonce) received from the client equals the challenge sent
  this._store.verify(req, challenge, (err, ok, ctx) => {
    validated(self, req, err, ok, ctx, clientData);
  });
};

module.exports = Strategy;
