import './shell.css';

export const metadata = {
  title: {
    default: 'WalletCordon — Give agents a wallet, not unlimited authority.',
    template: '%s — WalletCordon',
  },
  description: 'Deterministic policy, live protocol checks, and full transaction simulation between AI agents and wallet signing authority.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
