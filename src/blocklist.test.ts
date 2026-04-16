import { describe, expect, it } from 'vitest'
import { isPrivateIp } from './blocklist'

describe('isPrivateIp', () => {
  describe('IPv4 private ranges', () => {
    it('blocks 0.0.0.0/8 ("this network")', () => {
      expect(isPrivateIp('0.0.0.0')).toBe(true)
      expect(isPrivateIp('0.255.255.255')).toBe(true)
    })

    it('blocks 10.0.0.0/8 (RFC 1918)', () => {
      expect(isPrivateIp('10.0.0.1')).toBe(true)
      expect(isPrivateIp('10.255.255.255')).toBe(true)
    })

    it('blocks 100.64.0.0/10 (carrier-grade NAT)', () => {
      expect(isPrivateIp('100.64.0.1')).toBe(true)
      expect(isPrivateIp('100.127.255.255')).toBe(true)
    })

    it('blocks 127.0.0.0/8 (loopback)', () => {
      expect(isPrivateIp('127.0.0.1')).toBe(true)
      expect(isPrivateIp('127.255.255.255')).toBe(true)
    })

    it('blocks 169.254.0.0/16 (link-local / cloud metadata)', () => {
      expect(isPrivateIp('169.254.0.1')).toBe(true)
      expect(isPrivateIp('169.254.169.254')).toBe(true)
    })

    it('blocks 172.16.0.0/12 (RFC 1918)', () => {
      expect(isPrivateIp('172.16.0.1')).toBe(true)
      expect(isPrivateIp('172.31.255.255')).toBe(true)
    })

    it('blocks 192.0.0.0/24 (IETF protocol assignments)', () => {
      expect(isPrivateIp('192.0.0.1')).toBe(true)
      expect(isPrivateIp('192.0.0.255')).toBe(true)
    })

    it('blocks 192.168.0.0/16 (RFC 1918)', () => {
      expect(isPrivateIp('192.168.0.1')).toBe(true)
      expect(isPrivateIp('192.168.255.255')).toBe(true)
    })

    it('blocks 198.18.0.0/15 (benchmarking)', () => {
      expect(isPrivateIp('198.18.0.1')).toBe(true)
      expect(isPrivateIp('198.19.255.255')).toBe(true)
    })

    it('blocks 240.0.0.0/4 (reserved)', () => {
      expect(isPrivateIp('240.0.0.1')).toBe(true)
      expect(isPrivateIp('255.255.255.255')).toBe(true)
    })

    it('allows public IPv4 addresses', () => {
      expect(isPrivateIp('8.8.8.8')).toBe(false)
      expect(isPrivateIp('93.184.216.34')).toBe(false)
      expect(isPrivateIp('1.1.1.1')).toBe(false)
    })
  })

  describe('IPv6 private ranges', () => {
    it('blocks ::1 (loopback)', () => {
      expect(isPrivateIp('::1')).toBe(true)
    })

    it('blocks :: (unspecified)', () => {
      expect(isPrivateIp('::')).toBe(true)
    })

    it('blocks fc00::/7 (unique local)', () => {
      expect(isPrivateIp('fc00::1')).toBe(true)
      expect(isPrivateIp('fdff::1')).toBe(true)
    })

    it('blocks fe80::/10 (link-local)', () => {
      expect(isPrivateIp('fe80::1')).toBe(true)
    })

    it('blocks ::ffff:0:0:0/96 (SIIT IPv4-translated)', () => {
      expect(isPrivateIp('::ffff:0:0:1')).toBe(true)
    })

    it('blocks 64:ff9b::/96 (NAT64 well-known prefix)', () => {
      expect(isPrivateIp('64:ff9b::1')).toBe(true)
      expect(isPrivateIp('64:ff9b::7f00:1')).toBe(true)
    })

    it('blocks 64:ff9b:1::/48 (NAT64 local-use prefix)', () => {
      expect(isPrivateIp('64:ff9b:1::1')).toBe(true)
    })

    it('allows public IPv6 addresses', () => {
      expect(isPrivateIp('2606:4700:4700::1111')).toBe(false)
      expect(isPrivateIp('2001:4860:4860::8888')).toBe(false)
    })
  })

  describe('IPv4-mapped IPv6 bypass vectors', () => {
    it('blocks ::ffff:127.0.0.1 (IPv4-mapped loopback)', () => {
      expect(isPrivateIp('::ffff:127.0.0.1')).toBe(true)
    })

    it('blocks ::ffff:10.0.0.1 (IPv4-mapped private)', () => {
      expect(isPrivateIp('::ffff:10.0.0.1')).toBe(true)
    })

    it('blocks ::ffff:169.254.169.254 (IPv4-mapped metadata)', () => {
      expect(isPrivateIp('::ffff:169.254.169.254')).toBe(true)
    })

    it('blocks ::ffff:7f00:1 (IPv4-mapped loopback hex form)', () => {
      expect(isPrivateIp('::ffff:7f00:1')).toBe(true)
    })

    it('allows ::ffff:8.8.8.8 (IPv4-mapped public)', () => {
      expect(isPrivateIp('::ffff:8.8.8.8')).toBe(false)
    })
  })
})
