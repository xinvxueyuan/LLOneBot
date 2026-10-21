import { describe, it, expect } from 'vitest'
import { hashPassword, isEncodedScryptHash, legacyHashPassword, verifyPassword } from '@/webui/BE/passwordHash'

describe('passwordHash', () => {
  it('uses a random salt and verifies the encoded scrypt hash', async () => {
    const first = await hashPassword('my-secret-token')
    const second = await hashPassword('my-secret-token')

    expect(first).toMatch(/^scrypt\$16384\$8\$1\$[0-9a-f]+\$[0-9a-f]+$/)
    expect(second).not.toBe(first)
    expect(isEncodedScryptHash(first)).toBe(true)
    expect(await verifyPassword('my-secret-token', first)).toBe(true)
    expect(await verifyPassword('wrong-token', first)).toBe(false)
  })

  it('retains legacy SHA-256 derivation only for migration', () => {
    expect(legacyHashPassword('my-secret-token')).toHaveLength(64)
    expect(legacyHashPassword('my-secret-token')).toBe(legacyHashPassword('my-secret-token'))
  })

  it('rejects malformed encoded hashes', async () => {
    expect(await verifyPassword('secret', 'not-a-password-hash')).toBe(false)
    expect(isEncodedScryptHash('scrypt$999999999$8$1$' + '00'.repeat(16) + '$' + '00'.repeat(64))).toBe(false)
    expect(await verifyPassword('secret', 'scrypt$16384$8$1$' + 'GG'.repeat(16) + '$' + '00'.repeat(64))).toBe(false)
    expect(await verifyPassword('secret', 'scrypt$16384$8$1$' + '00'.repeat(16) + '$' + '00'.repeat(63))).toBe(false)
  })
})
