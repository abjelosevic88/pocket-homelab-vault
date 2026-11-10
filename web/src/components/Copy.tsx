// Copy to the clipboard; a copied secret is wiped again after the time set
// in Settings (if the clipboard still holds it).
import { useCallback } from 'react'
import { useApp } from '../lib/app-context'
import { copyText, useToast } from './ui'

let wipe: number | undefined

export function useCopy() {
  const { settings } = useApp()
  const { toast } = useToast()
  const after = settings?.clipboard_clear ?? 30
  return useCallback(async (text: string, what = 'Copied', secret = false) => {
    if (!text) return
    const ok = await copyText(text)
    if (!ok) { toast('Copying is blocked in this browser', 'err'); return }
    toast(secret && after ? `${what} copied · cleared in ${after} s` : `${what} copied`)
    if (secret && after) {
      clearTimeout(wipe)
      wipe = window.setTimeout(async () => {
        try { if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('') } catch { /* no permission to read: leave it */ }
      }, after * 1000)
    }
  }, [after, toast])
}
