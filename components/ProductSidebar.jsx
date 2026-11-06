import Link from 'next/link';

const tabs = [
  { href: '/runs', number: '01', label: 'Agent runs', key: 'runs' },
  { href: '/report', number: '02', label: 'Transaction report', key: 'report' },
  { href: '/policy', number: '03', label: 'Policy studio', key: 'policy' },
];

export default function ProductSidebar({ active }) {
  return (
    <aside className="sidebar" aria-label="WalletCordon product navigation">
      <Link className="brand" href="/" aria-label="WalletCordon home">
        <svg viewBox="0 0 36 36" aria-hidden="true"><path d="M7 8h22v20H7z" fill="none" stroke="currentColor" strokeWidth="2"/><path d="M12 13v10M24 13v10M12 18h12" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="square"/></svg>
        <span>WalletCordon</span>
      </Link>
      <nav className="side-nav">
        {tabs.map((tab) => (
          <Link key={tab.key} className={active === tab.key ? 'active' : undefined} href={tab.href} aria-current={active === tab.key ? 'page' : undefined}>
            <span>{tab.number}</span>{tab.label}
          </Link>
        ))}
      </nav>
      <div className="boundary-note">
        <span>SIGNING BOUNDARY</span>
        <p>The agent can propose a transaction. It never gets the key or direct access to the wallet.</p>
      </div>
      <a className="repo-link" href="https://github.com/x0rc1ph3r/eth-call-scout">Repository &amp; docs <span aria-hidden="true">↗</span></a>
    </aside>
  );
}
