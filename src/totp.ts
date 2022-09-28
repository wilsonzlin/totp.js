import encodeBase32 from "@xtjs/lib/js/encodeBase32";
import { createHmac, randomBytes } from "crypto";

const MESSAGE_REGENERATION_INTERVAL = 30;
const OTP_WINDOW = 1;
const OTP_SECRET_SIZE = 10;

const OTP_LENGTH = 6;

export const generateTotpSecret = () => randomBytes(OTP_SECRET_SIZE);

export const encodeTotpSecretForEndUser = (secret: Uint8Array) =>
  encodeBase32(secret);

const getTimestampMessage = () =>
  Math.floor(Date.now() / 1000 / MESSAGE_REGENERATION_INTERVAL);

const truncateHash = (hash: Uint8Array) => {
  const offset = hash[19] & 0xf;

  return (
    (((hash[offset] & 0x7f) << 24) |
      ((hash[offset + 1] & 0xff) << 16) |
      ((hash[offset + 2] & 0xff) << 8) |
      (hash[offset + 3] & 0xff)) %
    10 ** OTP_LENGTH
  );
};

export const generateTotp = (
  binarySecret: Uint8Array,
  timestampMessage: number = getTimestampMessage()
) => {
  const binaryTsm = Buffer.alloc(8);
  binaryTsm.writeInt32BE(timestampMessage, 4);
  const hash = createHmac("sha1", binarySecret).update(binaryTsm).digest();

  return truncateHash(hash);
};

export const verifyTotp = (secret: Uint8Array, code: number) => {
  if (!Number.isSafeInteger(code) || code < 0 || code > 999999) {
    return false;
  }
  const currentTsm = getTimestampMessage();

  for (
    let tsm = currentTsm - OTP_WINDOW;
    tsm <= currentTsm + OTP_WINDOW;
    tsm++
  ) {
    if (generateTotp(secret, tsm) == code) {
      return true;
    }
  }

  return false;
};
