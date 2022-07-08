#!/usr/bin/env node

// Import
import { ApiPromise, WsProvider } from '@polkadot/api';
import bip39 from 'bip39';
import crypto from 'crypto';
import fs from 'fs';
import Keyring from '@polkadot/keyring';
import { u8aToHex } from '@polkadot/util';
import { mnemonicToLegacySeed, hdEthereum } from '@polkadot/util-crypto';
import * as readlineSync from 'readline-sync';

let rpcUrl = 'wss://moonbeam-alpha.api.onfinality.io/public-ws'

function aesEncrypt(data, key) {
  const cipher = crypto.createCipher('aes192', key);
  var crypted = cipher.update(data, 'utf8', 'hex');
  crypted += cipher.final('hex');
  return crypted;
}

function aesDecrypt(encrypted, key) {
  const decipher = crypto.createDecipher('aes192', key);
  var decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function encryptMemToFile(mnemonic, path, passwd) {
  const data = aesEncrypt(mnemonic, passwd);
  fs.writeFileSync(path, data);
}
// 解密助记词
function decryptMemByFile(path, passwd) {
  try {
    const data = fs.readFileSync(path, 'utf-8');
    return aesDecrypt(data, passwd);
  } catch (error) {
    console.log(error)
    throw Error('decryptMemError')
  }
}

async function generateAccount(walletName, password) {

  // Import Ethereum account from mnemonic
  const keyringECDSA = new Keyring({ type: 'ethereum' });
  const mnemonic = bip39.generateMnemonic()
  encryptMemToFile(mnemonic, walletName, password)

  // Define index of the derivation path and the derivation path
  const index = 0;
  const ethDerPath = "m/44'/60'/0'/0/" + index;
  const subsDerPath = '//hard/soft';
  console.log(`Mnemonic: ${mnemonic}`);
  console.log(`--------------------------\n`);

  // Extract Ethereum address from mnemonic
  const newPairEth = keyringECDSA.addFromUri(`${mnemonic}/${ethDerPath}`);
  console.log(`Ethereum Derivation Path: ${ethDerPath}`);
  console.log(`Derived Ethereum Address from Mnemonic: ${newPairEth.address}`);

  // Extract private key from mnemonic
  const privateKey = u8aToHex(
    hdEthereum(mnemonicToLegacySeed(mnemonic, '', false, 64), ethDerPath).secretKey
  );
  const publicKey = u8aToHex(
    hdEthereum(mnemonicToLegacySeed(mnemonic, '', false, 64), ethDerPath).publicKey
  );
  console.log(`Derived Private Key from Mnemonic: ${privateKey}`);
  console.log(`Derived Public Key from Mnemonic: ${publicKey}`);
  console.log(`--------------------------\n`);

  // Extract address from private key
  const otherPair = await keyringECDSA.addFromUri(privateKey);
  console.log(`Derived Address from Private Key: ${otherPair.address}`);
}

async function getBalanceAndNonce(addr = '0x5A26cAfE424afB8d9F478CE3cCcD2E5572483053') {
  // Construct API provider
  const wsProvider = new WsProvider(rpcUrl);
  const api = await ApiPromise.create({ provider: wsProvider });

  // Define wallet address
  // const addr = '0xd0aedb77a9089f40a289247de3aab7cf7202df10';

  // Retrieve the last timestamp
  const now = await api.query.timestamp.now();

  // Retrieve the account balance & current nonce via the system module
  const { nonce, data: balance } = await api.query.system.account(addr);

  // Retrieve the given account's next index/nonce, taking txs in the pool into account
  const nextNonce = await api.rpc.system.accountNextIndex(addr);

  console.log(`${now}: balance of ${balance.free} and a current nonce of ${nonce} and next nonce of ${nextNonce}`);

}

async function getChainStatus() {
  // Construct API provider
  const wsProvider = new WsProvider(rpcUrl);
  const api = await ApiPromise.create({ provider: wsProvider });
  // Retrieve the chain name
  const chain = await api.rpc.system.chain();

  // Retrieve the latest header
  const lastHeader = await api.rpc.chain.getHeader();

  // Log the information
  console.log(`${chain}: last block #${lastHeader.number} has hash ${lastHeader.hash}`);

  // Subscribe to the new headers
  // await api.rpc.chain.subscribeNewHeads((lastHeader) => {
  //     console.log(`${chain}: last block #${lastHeader.number} has hash ${lastHeader.hash}`);
  //   });
}

async function transfer(sourceMem, to, amount) {
  const keyring = new Keyring({ type: 'ethereum' });
  // Construct API provider
  const wsProvider = new WsProvider(rpcUrl);
  const api = await ApiPromise.create({ provider: wsProvider });

  // Initialize wallet key pairs
  const alice = keyring.addFromUri(sourceMem);

  // Form the transaction
  const tx = await api.tx.balances
    .transfer(to, amount)

  // Retrieve the encoded calldata of the transaction
  const encodedCalldata = tx.method.toHex()
  console.log(encodedCalldata)

  // Sign and send the transaction
  const txHash = await tx
    .signAndSend(alice);

  // Show the transaction hash
  console.log(`Submitted with hash ${txHash}`);
  return
}

async function joinCandidates(sourceMem, bound, candidateCount) {
  const keyring = new Keyring({ type: 'ethereum' });
  // Construct API provider
  const wsProvider = new WsProvider(rpcUrl);
  const api = await ApiPromise.create({ provider: wsProvider });

  // Initialize wallet key pairs
  const alice = keyring.addFromUri(sourceMem);

  // Form the transaction
  const tx = await api.tx.parachainStaking
    .joinCandidates(bound, candidateCount)

  // Retrieve the encoded calldata of the transaction
  const encodedCalldata = tx.method.toHex()
  console.log(encodedCalldata)

  // Sign and send the transaction
  const txHash = await tx
    .signAndSend(alice);

  // Show the transaction hash
  console.log(`Submitted with hash ${txHash}`);
  return
}

async function setKeys(sourceMem, sessionKey) {
  const keyring = new Keyring({ type: 'ethereum' });
  // Construct API provider
  const wsProvider = new WsProvider(rpcUrl);
  const api = await ApiPromise.create({ provider: wsProvider });

  // Initialize wallet key pairs
  const alice = keyring.addFromUri(sourceMem);

  // Form the transaction
  const tx = await api.tx.authorMapping
    .setKeys(sessionKey)

  // Retrieve the encoded calldata of the transaction
  const encodedCalldata = tx.method.toHex()
  console.log(encodedCalldata)

  // Sign and send the transaction
  const txHash = await tx
    .signAndSend(alice);

  // Show the transaction hash
  console.log(`Submitted with hash ${txHash}`);
  return
}
async function main() {
  let args = process.argv.splice(2);
  const functionName = args[0];
  args.forEach(function(arg) {
    let r = arg.match(/--rpcUrl=(.+)/);
    if (r && r[1]) {
      rpcUrl = r[1];
    }

  })
  if (functionName == 'generateAccount') {
    const walletName = readlineSync.question('Wallet Name: ');
    const password = readlineSync.question('Password: ', { hideEchoBack: true });
    generateAccount(walletName, password);
  } else if (functionName == 'decryptMem') {
    const path = readlineSync.question('Wallet path: ');
    const password = readlineSync.question('Password: ', { hideEchoBack: true });
    console.log(decryptMemByFile(path, password));
  } else if (functionName == 'joinCandidates') {
    const path = readlineSync.question('Wallet path: ');
    const password = readlineSync.question('Password: ', { hideEchoBack: true });
    const bound = readlineSync.question('bound amount: ');
    const candidateCount = readlineSync.question('candidate count: ');
    const sourceMem = decryptMemByFile(path, password);
    joinCandidates(sourceMem, bound, candidateCount);
  } else if (functionName == 'setKeys') {
    const path = readlineSync.question('Wallet path: ');
    const password = readlineSync.question('Password: ', { hideEchoBack: true });
    const sessionKey = readlineSync.question('session key: ');
    const sourceMem = decryptMemByFile(path, password);
    setKeys(sourceMem, sessionKey)
  } else if (functionName == 'transfer') {
    const to = readlineSync.question('target address: ');
    const amount = readlineSync.question('amount: ');
    const path = readlineSync.question('Wallet path: ');
    const password = readlineSync.question('Password: ', { hideEchoBack: true });
    const sourceMem = decryptMemByFile(path, password);
    transfer(sourceMem, to, amount);
  } else if (functionName == 'getChainStatus') {
    getChainStatus();
  } else if (functionName == 'getBalanceAndNonce') {
    const address = readlineSync.question('Wallet address: ');
    getBalanceAndNonce(address);
  } else {
    console.log(`
    Please input Function Name as first Args:
    ==========================================================
    getChainStatus:     getChainStatus
    getBalanceAndNonce: getBalanceAndNonce

    generateAccount:    generate a new account and save to file after encrypto.
    decryptMem:         decryp mnemonic from encrypt file.
    joinCandidates:     send a parachainStaking.joinCandidates transaction.
    setKeys:            send a authorMapping.setKeys transaction.
    transfer:           transfer token to another address.
    ==========================================================
    --rpcUrl=wss://moonbeam-alpha.api.onfinality.io/public-ws
    `)
    return;
  }
}

main()