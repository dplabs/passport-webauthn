const expect = require("chai").expect;
const crypto = require("crypto");
const utils = require("../lib/utils");

function check(rpIDdomain, host) {
  const req = {
    headers: {
      host,
    },
  };
  const hash = crypto.createHash("sha256").update(rpIDdomain).digest();

  return utils.checkRPIDHash(req, hash);
}

describe("utils", function () {
  describe("RP ID hash", function () {
    it("should validate localhost", function () {
      expect(check("localhost", "localhost")).to.equal(true);
    });

    it("should validate same second level domain", function () {
      expect(check("example.com", "example.com")).to.equal(true);
    });

    it("should validate same second third domain", function () {
      expect(check("app.example.com", "app.example.com")).to.equal(true);
    });

    it("should validate domains at different level but within the same 2nd level", function () {
      expect(check("example.com", "app.example.com")).to.equal(true);
    });

    it("should not validate a lower specific domain", function () {
      expect(check("app.example.com", "example.com")).to.equal(false);
    });

    it("should not validate sibling domains", function () {
      expect(check("app.example.com", "api.example.com")).to.equal(false);
    });

    it("should not validate different domains", function () {
      expect(check("example.com", "test.com")).to.equal(false);
    });
  });
});
