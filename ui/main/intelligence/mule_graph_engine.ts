import {
  CryptoWalletTransaction,
  MaliciousApkFinding,
  MuleGraphData,
  MuleGraphEdge,
  MuleGraphNode,
  UnifiedUPITransaction
} from '../../shared/forensic-types';

/**
 * Interactive Mule Link Graph Engine.
 * Reconstructs multi-hop financial trails: Victim -> Layer 1 Mule VPA -> Layer 2 Bank -> Crypto USDT off-ramp.
 */
export class MuleGraphEngine {
  public static buildGraph(
    transactions: UnifiedUPITransaction[],
    cryptoTransactions: CryptoWalletTransaction[] = [],
    maliciousApks: MaliciousApkFinding[] = []
  ): MuleGraphData {
    const nodeMap = new Map<string, MuleGraphNode>();
    const edges: MuleGraphEdge[] = [];

    let totalTransferredInr = 0;
    let cryptoOffRampsCount = 0;

    // 1. Process UPI Transactions
    for (const tx of transactions) {
      if (tx.amountInr <= 0) continue;
      totalTransferredInr += tx.amountInr;

      const payerId = tx.payerVpa || (tx.accountMask ? `Bank_${tx.accountMask}` : 'Victim_Device');
      const payeeId = tx.payeeVpa || (tx.accountMask ? `Bank_${tx.accountMask}` : 'Unknown_Beneficiary');

      // Add payer node
      if (!nodeMap.has(payerId)) {
        nodeMap.set(payerId, {
          id: payerId,
          label: payerId,
          type: payerId.includes('@') ? 'VPA' : (payerId.startsWith('Bank_') ? 'BANK_ACCOUNT' : 'SUSPECT_DEVICE'),
          riskScore: 'LOW',
          details: { firstSeen: tx.timestamp.istFormatted }
        });
      }

      // Add payee node (potential mule)
      if (!nodeMap.has(payeeId)) {
        const isSuspicious = tx.amountInr >= 25000 || tx.corroboratedSources.includes('WAL_LOG');
        nodeMap.set(payeeId, {
          id: payeeId,
          label: payeeId,
          type: payeeId.includes('@') ? 'VPA' : (payeeId.startsWith('Bank_') ? 'BANK_ACCOUNT' : 'VPA'),
          riskScore: isSuspicious ? 'HIGH' : 'MEDIUM',
          details: { firstSeen: tx.timestamp.istFormatted, incomingTxCount: 1 }
        });
      } else {
        const node = nodeMap.get(payeeId)!;
        node.details.incomingTxCount = (node.details.incomingTxCount || 1) + 1;
        if (node.details.incomingTxCount >= 3) {
          node.riskScore = 'CRITICAL'; // Multi-payer high-volume mule funnel
        }
      }

      edges.push({
        id: `EDGE_${tx.id}`,
        source: payerId,
        target: payeeId,
        amountInr: tx.amountInr,
        utrNumber: tx.utrNumber || undefined,
        timestamp: tx.timestamp.istFormatted,
        app: tx.sourceApp,
        channel: 'UPI'
      });
    }

    // 2. Link Crypto Off-Ramps (Mule cashouts)
    for (const ctx of cryptoTransactions) {
      cryptoOffRampsCount++;
      const cryptoNodeId = `CRYPTO_${ctx.address.substring(0, 10)}`;

      if (!nodeMap.has(cryptoNodeId)) {
        nodeMap.set(cryptoNodeId, {
          id: cryptoNodeId,
          label: `TRC20 USDT: ${ctx.address.substring(0, 10)}...`,
          type: 'CRYPTO_WALLET',
          riskScore: 'CRITICAL',
          details: { coin: ctx.coin, fullAddress: ctx.address, txHash: ctx.txHash }
        });
      }

      // Find highest-volume mule node to anchor the crypto off-ramp edge
      let topMuleId = 'Mule_Layer1';
      for (const [id, node] of nodeMap.entries()) {
        if (node.riskScore === 'CRITICAL' || node.riskScore === 'HIGH') {
          topMuleId = id;
          break;
        }
      }

      edges.push({
        id: `CRYPTO_EDGE_${ctx.id}`,
        source: topMuleId,
        target: cryptoNodeId,
        amountInr: ctx.amount * 88, // Approx USDT to INR
        utrNumber: ctx.txHash.substring(0, 12),
        timestamp: ctx.timestamp.istFormatted,
        app: ctx.walletApp,
        channel: 'CRYPTO_TRANSFER'
      });
    }

    // 3. Link Malicious APK Telegram C2 Bots
    for (const apk of maliciousApks) {
      for (const bot of apk.extractedTelegramBotTokens) {
        const botNodeId = `TG_BOT_${bot.substring(0, 12)}`;
        if (!nodeMap.has(botNodeId)) {
          nodeMap.set(botNodeId, {
            id: botNodeId,
            label: `C2 Bot: ${bot.substring(0, 14)}...`,
            type: 'TELEGRAM_BOT',
            riskScore: 'CRITICAL',
            details: { fullToken: bot, malwarePkg: apk.packageName }
          });
        }

        edges.push({
          id: `EDGE_C2_${apk.packageName}`,
          source: 'Victim_Device',
          target: botNodeId,
          amountInr: 0,
          timestamp: new Date().toISOString(),
          app: 'Telegram_C2',
          channel: 'SMS_FORWARD'
        });
      }
    }

    return {
      nodes: Array.from(nodeMap.values()),
      edges,
      totalMuleHops: edges.length,
      totalTransferredInr,
      cryptoOffRampsCount
    };
  }
}
