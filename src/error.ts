export class SsrfError extends Error {
  readonly code: string
  readonly url: string

  constructor(code: string, message: string, url: string) {
    super(message)
    this.name = 'SsrfError'
    this.code = code
    this.url = url
  }
}
