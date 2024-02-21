exports.originalOrigin = function (req, options) {
  options = options || {};
  var app = req.app;
  if (app && app.get && app.get("trust proxy")) {
    options.proxy = true;
  }
  var trustProxy = options.proxy;

  var proto = (req.headers["x-forwarded-proto"] || "").toLowerCase(),
    tls =
      req.connection.encrypted ||
      (trustProxy && "https" == proto.split(/\s*,\s*/)[0]),
    host = (trustProxy && req.headers["x-forwarded-host"]) || req.headers.host,
    protocol = tls ? "https" : "http";
  return protocol + "://" + host;
};

exports.getRPID = function (req) {
  // const origin = req.origin || (req.get && req.get("origin"));
  // TODO: where is the rpID in the user request params?
  // const rpID =
  //   clientData.rpID || url.parse(origin).hostname || effectiveDomain;

  return "TODO";
};

exports.getEffectiveDomain = function (req) {
  return "TODO";
};
