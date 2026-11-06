# Attacker list

Keybound ships with a list of known attacker and exploiter addresses. It is always on, and a policy cannot switch it off. If a transaction would pay, approve, call or name a listed address, it is denied and a critical alert is written.

This protects the wallet when a bot is compromised and tries to send funds to a known thief. It is a backstop, not a full defense: a brand-new attacker address will not be on any list, so default-deny rules and spend limits still do most of the work.

## Where it is checked

| When | What is checked | Result |
|---|---|---|
| Before simulation | The target, every byte of the calldata (including packed swap paths), and EIP-7702 delegates | `attacker:target`, `attacker:calldata`, `attacker:delegate` |
| In simulation | Every call, token transfer, approval and state change, including transfers the wallet did not make itself | `attacker:effects`. One source reporting a hit is enough to deny |
| After mining | The real transaction, its logs, and every internal call, including ETH transfers that emit no log | `onchain:attacker`, plus a critical alert |
| Writing a policy | Contracts, recipients and spenders the policy tries to allow | `attacker-in-policy`, and the policy is refused |

Every receipt records the list's version and hash, and the hash is part of the decision fingerprint. Receiving tokens *from* a listed address does not deny a call.

## Free API

Public, read-only, and needs no key. Responses can be read from any website, and they are cached to keep hosting free.

| Request | Returns |
|---|---|
| `GET /api/v1/attackers` | The whole list, in the same JSON the guard loads |
| `GET /api/v1/attackers?view=meta` | Version, hash, count and sources, to check for changes cheaply |
| `GET /api/v1/attackers?view=addresses` | A plain array of addresses |
| `GET /api/v1/attackers/0x...` | Whether one address is listed, and why |

```sh
curl https://YOUR-DEPLOYMENT/api/v1/attackers/0x489A8756C18C0b8B24EC2a2b9FF3D4d447F79BEc
```

```json
{
  "address": "0x489a8756c18c0b8b24ec2a2b9ff3d4d447f79bec",
  "listed": true,
  "label": "BNB Bridge Exploiter (Binance cross-chain bridge, October 2022)",
  "sources": ["curated", "forta-etherscan-malicious"],
  "reference": "https://hub.elliptic.co/analysis/attack-mints-569-million-worth-of-bnb-tokens-in-bsc-bridge-exploit/",
  "listVersion": "2026-11-06",
  "listHash": "..."
}
```

The full list response also sends `x-keybound-list-hash` and an `ETag`. Send `If-None-Match` to get `304 Not Modified` when nothing changed.

The same file is free without any server: `https://raw.githubusercontent.com/x0rc1ph3r/eth-call-scout/main/data/attacker-addresses.json`.

## Getting the latest list

```sh
npx keybound attackers info
npx keybound attackers check 0x489A8756C18C0b8B24EC2a2b9FF3D4d447F79BEc
npx keybound attackers update
npx keybound attackers update --from https://YOUR-DEPLOYMENT/api/v1/attackers
```

`update` saves to `.keybound/attacker-addresses.json`, and the guard adds that file to the shipped list the next time it starts. Set `KEYBOUND_ATTACKER_LIST_FILE` or `KEYBOUND_ATTACKER_LIST_URL` to change where it reads from.

An update can only add addresses. A hacked or broken list server cannot remove an attacker, and it cannot list the protocols in the registry, gas rules and default rule sets, so it cannot use the list to stop honest swaps. A damaged local file is reported and ignored, and the shipped list still applies.

## Adding an address

- **Just for your wallet:** add it to `blockedAddresses` in your policy, or in the policy builder.
- **For everyone:** add it to `data/attacker-addresses.curated.json` with a reference that names the address, and open a pull request.

The API has no public way to write to the list. Anyone could otherwise block any address, including a rival's contract or a popular token.

## How it stays current

`.github/workflows/attackers-sync.yml` runs every day. When the feeds contain new addresses it opens a pull request, and merging it publishes the new list through the API and the raw file. To allow this, turn on **Allow GitHub Actions to create and approve pull requests** in the repository's Actions settings.

To refresh by hand:

```sh
npm run attackers:sync
```

## Sources and licenses

| Source | Contents | License |
|---|---|---|
| `curated` | Hand-checked addresses that the feeds miss | This project |
| [OFAC list](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses) | Sanctioned Ethereum addresses | MIT |
| [Forta labelled datasets](https://github.com/forta-network/labelled-datasets) | Exploit contracts, phishing and malicious labels. Last updated January 2023 | MIT |

[ScamSniffer's database](https://github.com/scamsniffer/scam-database) is larger and updated often, but it is GPL-3.0, so it is not in the shipped file. To add it to your own copy, run `node scripts/build-attacker-list.js --with-scamsniffer`. Check what that license means for you before redistributing the result.
