// Using the vault from the Bitwarden apps: the one address to enter, step by
// step for each app.
import { useApp } from '../lib/app-context'
import { useVault } from '../lib/vault-context'
import { useCopy } from '../components/Copy'
import { Icon } from '../components/icons'
import { Card, PageHeader } from '../components/ui'

export default function Apps() {
  const { status } = useVault()
  const { settings } = useApp()
  const copy = useCopy()
  const url = status?.server_url || settings?.base_url || window.location.origin
  const email = status?.email || ''
  const Steps = ({ steps }: { steps: React.ReactNode[] }) => <ol className="steps">{steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
  const server = <><b>Self-hosted</b> → Server URL <code>{url}</code></>
  return (
    <div className="page narrow">
      <PageHeader title="Bitwarden apps" sub="Your vault works in the official Bitwarden apps. Point them at this server and sign in with your email and master password." />
      <Card>
        <div className="apps-url">
          <div className="grow"><span className="muted small">Server address</span><div className="mono apps-url-v">{url}</div></div>
          <button type="button" className="btn primary" onClick={() => copy(url, 'Address')}><Icon name="copy" size={15} />Copy</button>
        </div>
        <div className="apps-url">
          <div className="grow"><span className="muted small">Email</span><div className="mono apps-url-v">{email}</div></div>
          <button type="button" className="btn" onClick={() => copy(email, 'Email')}><Icon name="copy" size={15} />Copy</button>
        </div>
        <p className="muted small">{status?.live_apps ? `${status.live_apps} app${status.live_apps === 1 ? ' is' : 's are'} connected for live sync right now.` : 'Apps with live sync (the browser extension, desktop) pick up changes the moment they happen; phones when you open them.'}</p>
      </Card>
      <Card title="Browser extension" sub="Chrome, Firefox, Safari, Edge, Brave, Vivaldi, Opera.">
        <Steps steps={[<>Install <b>Bitwarden</b> from your browser’s extension store.</>, <>Open it. Under <b>Accessing</b>, choose {server}, then Save.</>, <>Sign in with <code>{email}</code> and your master password.</>]} />
      </Card>
      <Card title="iPhone, iPad and Android" sub="The Bitwarden app from the App Store or Google Play.">
        <Steps steps={[<>On the sign-in screen, tap the region (<b>bitwarden.com</b>) and choose {server}.</>, <>Sign in with your email and master password.</>,
          <>To fill passwords in other apps: iPhone — Settings → General → AutoFill &amp; Passwords → Bitwarden. Android — Bitwarden → Settings → Auto-fill.</>,
          <>Phones sync when you open the app or pull down the list (there are no push messages from your own server).</>]} />
      </Card>
      <Card title="Desktop app" sub="Windows, macOS and Linux.">
        <Steps steps={[<>Install Bitwarden from bitwarden.com/download or your app store.</>, <>On the sign-in screen choose {server}.</>, <>Sign in. Unlock with Touch ID or Windows Hello in its settings if you like.</>]} />
      </Card>
      <Card title="Command line (bw)">
        <pre className="set-pre mono">{`bw config server ${url}\nbw login ${email}`}</pre>
      </Card>
      <p className="muted small">Not available here yet: sharing with others (organisations), attachments, Send, emergency access and passkey sign-in to the vault itself. Passkeys you save for websites work.</p>
    </div>
  )
}
