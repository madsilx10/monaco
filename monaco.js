// monaco.js
const { ethers } = require('ethers');
const fs = require('fs');
const crypto = require('crypto');
const ed = require('@noble/ed25519');
const { sha512 } = require('@noble/hashes/sha512');

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

const BASE_URL = 'https://staging.apimonaco.xyz';
const PRIVY_URL = 'https://auth.privy.io';
const PRIVY_APP_ID = 'cmpeq3sma00000dlam52l6tjt';
const PRIVY_CLIENT_ID = 'client-WY6ZY2XocmM5e9tFztEzrF5juwc7Uxe95iS8S1y5CeNw9';
const CHAIN_ID = 1328;

const baseHeaders = {
  'Accept': '*/*',
  'Content-Type': 'application/json',
  'Origin': 'https://trade.0xmonaco.com',
  'Referer': 'https://trade.0xmonaco.com/',
  'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
};

const privyHeaders = {
  ...baseHeaders,
  'Privy-App-Id': PRIVY_APP_ID,
  'Privy-Ca-Id': '1229a8c1-b612-494e-8381-59dda2c56e00',
  'Privy-Client': 'react-auth:3.34.0',
  'Privy-Client-Id': PRIVY_CLIENT_ID,
};

function buildSiweMsg(address, nonce) {
  const issuedAt = new Date().toISOString();
  return `trade.0xmonaco.com wants you to sign in with your Ethereum account:\n${address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://trade.0xmonaco.com\nVersion: 1\nChain ID: ${CHAIN_ID}\nNonce: ${nonce}\nIssued At: ${issuedAt}\nResources:\n- https://privy.io`;
}

async function connectWallet(privkey) {
  const wallet = new ethers.Wallet(privkey);
  const address = wallet.address;
  console.log(`\n[+] ${address}`);

  const sessionPriv = ed.utils.randomPrivateKey();
  const sessionPub = ed.getPublicKey(sessionPriv);
  const sessionPublicKey = Buffer.from(sessionPub).toString('hex');
  const clientId = crypto.randomUUID();

  // 1. Privy init
  process.stdout.write('[*] Privy init... ');
  const initRes = await fetch(`${PRIVY_URL}/api/v1/siwe/init`, {
    method: 'POST',
    headers: privyHeaders,
    body: JSON.stringify({ address }),
  }).then(r => r.json());

  if (!initRes.nonce) throw new Error('Privy init gagal: ' + JSON.stringify(initRes));
  console.log('OK');

  // 2. Privy authenticate
  process.stdout.write('[*] Privy auth... ');
  const siweMsg = buildSiweMsg(address, initRes.nonce);
  const privySig = await wallet.signMessage(siweMsg);

  const authRes = await fetch(`${PRIVY_URL}/api/v1/siwe/authenticate`, {
    method: 'POST',
    headers: privyHeaders,
    body: JSON.stringify({
      message: siweMsg,
      signature: privySig,
      chainId: `eip155:${CHAIN_ID}`,
      walletClientType: 'metamask',
      connectorType: 'injected',
      mode: 'login-or-sign-up',
    }),
  }).then(r => r.json());

  if (!authRes.token) throw new Error('Privy auth gagal: ' + JSON.stringify(authRes));
  console.log('OK');

  // 3. Monaco challenge
  process.stdout.write('[*] Monaco challenge... ');
  const challengeRes = await fetch(`${BASE_URL}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: baseHeaders,
    body: JSON.stringify({ address, chainId: CHAIN_ID, clientId, sessionPublicKey }),
  }).then(r => r.json());

  if (!challengeRes.message) throw new Error('Challenge gagal: ' + JSON.stringify(challengeRes));
  console.log('OK');

  // 4. Monaco verify
  process.stdout.write('[*] Monaco verify... ');
  const monacoSig = await wallet.signMessage(challengeRes.message);

  const verifyRes = await fetch(`${BASE_URL}/api/v1/auth/verify`, {
    method: 'POST',
    headers: baseHeaders,
    body: JSON.stringify({
      address,
      chainId: CHAIN_ID,
      clientId,
      nonce: challengeRes.nonce,
      sessionPublicKey,
      signature: monacoSig,
    }),
  }).then(r => r.json());

  if (!verifyRes.user) throw new Error('Verify gagal: ' + JSON.stringify(verifyRes));
  console.log('OK');
  console.log(`[+] User ID: ${verifyRes.user.id}`);

  return {
    address,
    clientId,
    sessionPublicKey,
    sessionPrivkey: Buffer.from(sessionPriv).toString('hex'),
    privyToken: authRes.privy_access_token,
    refreshToken: authRes.refresh_token,
    expiresAt: verifyRes.expiresAt,
  };
}

async function main() {
  const privkeys = fs.readFileSync('wallet.txt', 'utf8')
    .trim().split('\n').map(l => l.trim()).filter(Boolean);
  console.log(`[*] ${privkeys.length} wallet`);

  const sessions = [];
  for (const pk of privkeys) {
    try {
      const s = await connectWallet(pk);
      sessions.push(s);
    } catch (e) {
      console.log(`[-] Error: ${e.message}`);
    }
  }

  fs.writeFileSync('sessions.json', JSON.stringify(sessions, null, 2));
  console.log(`\n[+] ${sessions.length}/${privkeys.length} berhasil`);
  console.log('[+] Tersimpan di sessions.json');
}

main().catch(console.error);
