// monaco.js
const { ethers } = require('ethers');
const fs = require('fs');
const crypto = require('crypto');
const nacl = require('tweetnacl');

const BASE_URL = 'https://staging.apimonaco.xyz';
const PRIVY_URL = 'https://auth.privy.io';
const PRIVY_APP_ID = 'cmpeq3sma00000dlam52l6tjt';
const PRIVY_CLIENT_ID = 'client-WY6ZY2XocmM5e9tFztEzrF5juwc7Uxe95iS8S1y5CeNw9';
const CHAIN_ID = 1328;

const baseHeaders = {
  'Accept': '*/*',
  'Accept-Encoding': 'gzip, deflate, br, zstd',
  'Accept-Language': 'id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7',
  'Content-Type': 'application/json',
  'Origin': 'https://trade.0xmonaco.com',
  'Referer': 'https://trade.0xmonaco.com/',
  'Sec-Ch-Ua': '"Mises";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
  'Sec-Ch-Ua-Mobile': '?1',
  'Sec-Ch-Ua-Platform': '"Android"',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'cross-site',
  'User-Agent': 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
};

const privyHeaders = {
  ...baseHeaders,
  'Sec-Fetch-Site': 'cross-site',
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

  const keypair = nacl.sign.keyPair();
  const sessionPublicKey = Buffer.from(keypair.publicKey).toString('hex');
  const sessionPrivkey = Buffer.from(keypair.secretKey).toString('hex');


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
  console.log('[AUTH]', JSON.stringify(authRes));
  console.log('OK');

  // 3. Monaco challenge
  process.stdout.write('[*] Monaco challenge... ');
  const challengeRes = await fetch(`${BASE_URL}/api/v1/auth/challenge`, {
    method: 'POST',
    headers: baseHeaders,
    body: JSON.stringify({ address, chainId: CHAIN_ID, clientId: PRIVY_CLIENT_ID, sessionPublicKey }),
  });
  const challengeText = await challengeRes.text();
  let challengeJson;
  try {
    challengeJson = JSON.parse(challengeText);
  } catch(e) {
    throw new Error('Challenge CF block: ' + challengeText.slice(0, 100));
  }
  if (!challengeJson.message || challengeJson.error) throw new Error('Challenge gagal: ' + JSON.stringify(challengeJson));
  console.log('OK');

  // 4. Monaco verify
  process.stdout.write('[*] Monaco verify... ');
  const monacoSig = await wallet.signMessage(challengeJson.message);

  const verifyRes = await fetch(`${BASE_URL}/api/v1/auth/verify`, {
    method: 'POST',
    headers: baseHeaders,
    body: JSON.stringify({
      address,
      chainId: CHAIN_ID,
      clientId,
      nonce: challengeJson.nonce,
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
    sessionPrivkey,
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
