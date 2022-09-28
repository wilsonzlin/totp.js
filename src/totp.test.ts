import {
  encodeTotpSecretForEndUser,
  generateTotp,
  generateTotpSecret,
  verifyTotp,
} from "./totp";

test("generates TOTP code", () => {
  const secret = generateTotpSecret();
  expect(secret.byteLength).toBe(10);
  expect(encodeTotpSecretForEndUser(secret)).toMatch(/^[A-Z0-7]{16}$/);
  const code = generateTotp(secret);
  expect(code.toString()).toMatch(/^[0-9]{6}$/);
  expect(verifyTotp(secret, code)).toBe(true);
});

test("encodes Base32 correctly", () => {
  expect(
    encodeTotpSecretForEndUser(Buffer.from("abcde", "utf8"))
  ).toStrictEqual("MFRGGZDF");
  expect(
    encodeTotpSecretForEndUser(Buffer.from("04ad73f1ff10aa2d33ef", "hex"))
  ).toStrictEqual("ASWXH4P7CCVC2M7P");
});

test("verifies correctly", () => {
  const secret = Buffer.alloc(10);
  const ts = 53761413;
  const code = 431131;
  expect(generateTotp(secret, ts)).toStrictEqual(code);
});
