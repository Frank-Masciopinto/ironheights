export function signer() {
  const privateKey =
    process.env.PRIVATE_KEY || '0x0123456789abcdeffedcba9876543210aaaabbbbccccdddd1111222233334444';
  return privateKey;
}
