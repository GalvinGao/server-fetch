import { BlockList, isIPv6 } from 'node:net'

const blocklist = new BlockList()

// IPv4
blocklist.addSubnet('0.0.0.0', 8, 'ipv4') // "this network" (RFC 1122)
blocklist.addSubnet('10.0.0.0', 8, 'ipv4') // private (RFC 1918)
blocklist.addSubnet('100.64.0.0', 10, 'ipv4') // carrier-grade NAT (RFC 6598)
blocklist.addSubnet('127.0.0.0', 8, 'ipv4') // loopback
blocklist.addSubnet('169.254.0.0', 16, 'ipv4') // link-local (includes cloud metadata 169.254.169.254)
blocklist.addSubnet('172.16.0.0', 12, 'ipv4') // private (RFC 1918)
blocklist.addSubnet('192.0.0.0', 24, 'ipv4') // IETF protocol assignments (RFC 6890)
blocklist.addSubnet('192.168.0.0', 16, 'ipv4') // private (RFC 1918)
blocklist.addSubnet('198.18.0.0', 15, 'ipv4') // benchmarking (RFC 2544)
blocklist.addSubnet('240.0.0.0', 4, 'ipv4') // reserved for future use

// IPv6
blocklist.addSubnet('::1', 128, 'ipv6') // loopback
blocklist.addSubnet('::', 128, 'ipv6') // unspecified
blocklist.addSubnet('fc00::', 7, 'ipv6') // unique local (RFC 4193)
blocklist.addSubnet('fe80::', 10, 'ipv6') // link-local
blocklist.addSubnet('::ffff:0:0:0', 96, 'ipv6') // SIIT IPv4-translated (RFC 6052)
blocklist.addSubnet('64:ff9b::', 96, 'ipv6') // NAT64 well-known prefix (RFC 6052)
blocklist.addSubnet('64:ff9b:1::', 48, 'ipv6') // NAT64 local-use prefix (RFC 8215)

export function isPrivateIp(ip: string): boolean {
  return blocklist.check(ip, isIPv6(ip) ? 'ipv6' : 'ipv4')
}
