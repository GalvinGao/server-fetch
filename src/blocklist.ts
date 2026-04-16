import { BlockList } from 'node:net'

const blocklist = new BlockList()

export function isPrivateIp(ip: string): boolean {
  return blocklist.check(ip)
}
