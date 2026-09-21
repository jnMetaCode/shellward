export function log(event: string, detail: string) {
  console.log(new Date().toISOString(), event, detail)
}
