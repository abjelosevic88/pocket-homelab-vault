export interface User { id: number; email: string; name: string; role: 'admin' | 'member'; created_at: string }
export interface APIToken { id: number; user_id: number; name: string; prefix: string; last_used_at: string | null; created_at: string }

export type ConnMode = 'core' | 'direct' | 'off'
export type ConnVia = '' | 'core' | 'direct'

export interface GenSettings { kind: 'password' | 'passphrase'; length: number; upper: boolean; lower: boolean; digits: boolean; symbols: boolean; avoid: boolean; words: number; separator: string; capital: boolean; number: boolean }

export interface Settings {
  core_configured: boolean
  core_registered?: boolean
  title: string; date_format: string; time_format: string; week_start: number
  lock_minutes: number; clipboard_clear: number; show_icons: boolean; breach_check: boolean; share_health: boolean; generator: GenSettings
  notify_new_device: boolean; notify_failed: boolean; notify_security: boolean
  notify_url: string; notify_format: string; notify_configured: boolean
  renewals_mode: ConnMode; renewals_via: ConnVia; renewals_detail: string; renewals_open_url: string; renewals_configured: boolean
  renewals_url: string; renewals_token: string; renewals_public_url: string
  setup_complete: boolean; base_url: string; icon_service: string
}

export interface VaultEvent { id: number; kind: string; device_name: string; device_type: number | null; ip: string; detail: string; at: string }
export interface VaultDevice { id: string; name: string; type: number; type_name: string; kind: 'phone' | 'extension' | 'desktop' | 'web' | 'cli'; created_at: string; last_used: string; ip: string; push: boolean }
export interface Reminder { cipher_id: string; renewal_id: number; title: string; expires_on: string; created_at: string }
