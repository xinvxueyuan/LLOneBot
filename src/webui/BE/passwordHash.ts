import crypto from 'node:crypto'

const SCRYPT_PREFIX = 'scrypt'
const SCRYPT_KEY_LENGTH = 64
const SCRYPT_COST = 16_384
const SCRYPT_BLOCK_SIZE = 8
const SCRYPT_PARALLELIZATION = 1
const SCRYPT_SALT_LENGTH = 16
const SCRYPT_MAXMEM = 32 * 1024 * 1024

/** Calculate the legacy client-side SHA-256 token for one-time migration. */
export function legacyHashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex')
}

function parseEncodedHash(encodedHash: string): { salt: Buffer; expected: Buffer } | null {
  const parts = encodedHash.split('$')
  if (parts.length !== 6 || parts[0] !== SCRYPT_PREFIX) return null

  const [, cost, blockSize, parallelization, saltHex, hashHex] = parts
  if (cost !== String(SCRYPT_COST) || blockSize !== String(SCRYPT_BLOCK_SIZE) || parallelization !== String(SCRYPT_PARALLELIZATION)) return null
  if (!new RegExp(`^[0-9a-f]{${SCRYPT_SALT_LENGTH * 2}}$`).test(saltHex)) return null
  if (!new RegExp(`^[0-9a-f]{${SCRYPT_KEY_LENGTH * 2}}$`).test(hashHex)) return null

  return { salt: Buffer.from(saltHex, 'hex'), expected: Buffer.from(hashHex, 'hex') }
}

/** Whether a value is a valid, fixed-cost encoded verifier (not merely scrypt-prefixed). */
export function isEncodedScryptHash(encodedHash: string): boolean {
  return parseEncodedHash(encodedHash) !== null
}

function scrypt(password: string, salt: Buffer, keyLength: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, keyLength, {
      N: SCRYPT_COST,
      r: SCRYPT_BLOCK_SIZE,
      p: SCRYPT_PARALLELIZATION,
      maxmem: SCRYPT_MAXMEM,
    }, (error, derivedKey) => error ? reject(error) : resolve(derivedKey))
  })
}

/** Hash a client token with a random salt into the fixed scrypt storage format. */
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(SCRYPT_SALT_LENGTH)
  const derivedKey = await scrypt(password, salt, SCRYPT_KEY_LENGTH)
  return [SCRYPT_PREFIX, SCRYPT_COST, SCRYPT_BLOCK_SIZE, SCRYPT_PARALLELIZATION, salt.toString('hex'), derivedKey.toString('hex')].join('$')
}

/** Verify a token asynchronously against the strict encoded scrypt representation. */
export async function verifyPassword(password: string, encodedHash: string): Promise<boolean> {
  const parsed = parseEncodedHash(encodedHash)
  if (!parsed) return false

  try {
    const actual = await scrypt(password, parsed.salt, parsed.expected.length)
    return crypto.timingSafeEqual(actual, parsed.expected)
  } catch {
    return false
  }
}
