const base64url = require("base64url");
const crypto = require("crypto");
const url = require("url");

function origin(req) {
  return req.origin || (req.get && req.get("origin")) || host(req);
}
exports.origin = origin;

function host(req, options) {
  options = options || {};
  const app = req.app;
  if (app && app.get && app.get("trust proxy")) {
    options.proxy = true;
  }
  const trustProxy = options.proxy;

  const proto = (req.headers["x-forwarded-proto"] || "").toLowerCase(),
    tls =
      req.connection.encrypted ||
      (trustProxy && "https" == proto.split(/\s*,\s*/)[0]),
    host = (trustProxy && req.headers["x-forwarded-host"]) || req.headers.host,
    protocol = tls ? "https" : "http";
  return protocol + "://" + host;
}

function checkRPIDHash(req, rpIDHash) {
  const localhost = host(req);
  const effectiveDomain = url.parse(localhost).hostname;
  const effectiveDomainParts = effectiveDomain.split(".");

  let valid = false;

  // validate from the longes domain level up to two levels agains the rpIDHash
  do {
    const domain = effectiveDomainParts.join(".");
    const domainHash = crypto.createHash("sha256").update(domain).digest();
    valid = domainHash.equals(rpIDHash);
    effectiveDomainParts.shift();
  } while (!valid && effectiveDomainParts.length >= 2);

  return valid;
}
exports.checkRPIDHash = checkRPIDHash;

function verificationDone(
  self,
  err,
  user,
  publicKey,
  info,
  { clientDataJSON, b_authenticatorData, authenticatorData, response, id },
) {
  if (err) {
    return self.error(err);
  }
  if (!user) {
    return self.fail(publicKey);
  }

  const hash = crypto.createHash("sha256").update(clientDataJSON).digest();
  const data = Buffer.concat([b_authenticatorData, hash]);
  const signature = base64url.toBuffer(response.signature);

  // Verify that the signature is valid.
  const ok = crypto
    .createVerify("sha256")
    .update(data)
    .verify(publicKey, signature);
  if (!ok) {
    return self.fail({ message: "Invalid signature" }, 403);
  }

  // If the application desires, allow it to process the signature counter
  // in order to detect cloned authenticators and incorporate this
  // information into risk scoring.
  if (authenticatorData.signCount && info && info.signCount) {
    self._verifySignCount(
      id,
      authenticatorData.signCount,
      info.signCount,
      function (err, ok) {
        if (err) {
          return self.error(err);
        }
        if (!ok) {
          return self.fail({ message: "Cloned authenticator detected" }, 403);
        }
        self.success(user, info);
      },
    );
  } else {
    self.success(user, info);
  }
}
exports.verificationDone = verificationDone;

function registrationDone(self, err, user, info) {
  if (err) {
    return self.error(err);
  }
  if (!user) {
    return self.fail(info);
  }
  self.success(user, info);
}
exports.registrationDone = registrationDone;
