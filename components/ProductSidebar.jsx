import Link from 'next/link';

const tabs = [
  { href: '/runs', number: '01', label: 'Agent runs', key: 'runs' },
  { href: '/report', number: '02', label: 'Call report', key: 'report' },
  { href: '/policy', number: '03', label: 'Policy studio', key: 'policy' },
];

export default function ProductSidebar({ active }) {
  return (
    <aside className="sidebar" aria-label="Keybound product navigation">
      <Link className="brand" href="/" aria-label="Keybound home">
        <svg viewBox="0 0 36 36" aria-hidden="true"><path d="M18 2.5 31 7.7v9.5c0 8.1-5.4 13.5-13 16.3-7.6-2.8-13-8.2-13-16.3V7.7L18 2.5Z" fill="none" stroke="currentColor" strokeWidth="2"/><path d="M11 18h4l2-6 3 12 2-6h4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
        <span>Keybound</span>
      </Link>
      <nav className="side-nav">
        {tabs.map((tab) => (
          <Link key={tab.key} className={active === tab.key ? 'active' : undefined} href={tab.href} aria-current={active === tab.key ? 'page' : undefined}>
            <span>{tab.number}</span>{tab.label}
          </Link>
        ))}
      </nav>
      <div className="boundary-note">
        <span>TRUST BOUNDARY</span>
        <p>The agent proposes. Deterministic code alone can authorize.</p>
      </div>
      <a className="repo-link" href="https://github.com/x0rc1ph3r/eth-call-scout">Source &amp; docs <span aria-hidden="true">↗</span></a>
    </aside>
  );
}
