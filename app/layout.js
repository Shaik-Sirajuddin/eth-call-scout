import './shell.css';

export const metadata = {
  title: {
    default: 'Keybound — AI proposes. Policy decides. Wallet signs.',
    template: '%s — Keybound',
  },
  description: 'Deterministic wallet authorization and live protocol defense for AI agents.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
