import { UnifiedUPITransaction } from '../../../shared/forensic-types';

/**
 * Indian UPI Cross-Artifact Correlation Engine.
 * Correlates and fuses transactions across App DBs (PhonePe, GPay, Paytm), WAL frames,
 * SMS DLT banking ledgers, and Android Notification logs into unified Master Ledger records.
 */
export class UpiCorrelator {
  public static correlate(allTransactions: UnifiedUPITransaction[]): UnifiedUPITransaction[] {
    const utrMap = new Map<string, UnifiedUPITransaction>();
    const nonUtrList: UnifiedUPITransaction[] = [];

    // 1. Group by 12-digit NPCI UTR number
    for (const tx of allTransactions) {
      if (tx.utrNumber && tx.utrNumber.length === 12) {
        if (!utrMap.has(tx.utrNumber)) {
          // Initialize master entry
          utrMap.set(tx.utrNumber, {
            ...tx,
            corroboratedSources: [...tx.corroboratedSources]
          });
        } else {
          // Fuse records
          const existing = utrMap.get(tx.utrNumber)!;
          UpiCorrelator.fuseTransactions(existing, tx);
        }
      } else {
        nonUtrList.push({
          ...tx,
          corroboratedSources: [...tx.corroboratedSources]
        });
      }
    }

    // 2. Correlate non-UTR transactions (e.g. from app intent or notification) by amount + timestamp proximity (within 60 seconds)
    const masterTransactions = Array.from(utrMap.values());
    const remainingUncorrelated: UnifiedUPITransaction[] = [];

    for (const nonUtr of nonUtrList) {
      let matched = false;
      for (const master of masterTransactions) {
        if (
          master.amountInr > 0 &&
          nonUtr.amountInr > 0 &&
          Math.abs(master.amountInr - nonUtr.amountInr) < 0.01 &&
          Math.abs(master.timestamp.epochMs - nonUtr.timestamp.epochMs) < 60000
        ) {
          UpiCorrelator.fuseTransactions(master, nonUtr);
          matched = true;
          break;
        }
      }

      if (!matched) {
        remainingUncorrelated.push(nonUtr);
      }
    }

    // Sort by timestamp descending
    const combined = [...masterTransactions, ...remainingUncorrelated];
    combined.sort((a, b) => b.timestamp.epochMs - a.timestamp.epochMs);

    return combined;
  }

  private static fuseTransactions(master: UnifiedUPITransaction, incoming: UnifiedUPITransaction): void {
    // Add corroborated source tags
    for (const src of incoming.corroboratedSources) {
      if (!master.corroboratedSources.includes(src)) {
        master.corroboratedSources.push(src);
      }
    }

    // Fill missing metadata from incoming
    if (!master.payeeVpa && incoming.payeeVpa) master.payeeVpa = incoming.payeeVpa;
    if (!master.payerVpa && incoming.payerVpa) master.payerVpa = incoming.payerVpa;
    if (!master.accountMask && incoming.accountMask) master.accountMask = incoming.accountMask;
    if (!master.appTransactionId && incoming.appTransactionId) master.appTransactionId = incoming.appTransactionId;
    if (master.amountInr === 0 && incoming.amountInr > 0) master.amountInr = incoming.amountInr;
    if (!master.embeddedIdTimestamp && incoming.embeddedIdTimestamp) {
      master.embeddedIdTimestamp = incoming.embeddedIdTimestamp;
      master.clockTamperDetected = incoming.clockTamperDetected;
    }

    // If master was only from SMS/Notif, but incoming is from App DB/WAL, upgrade sourceApp
    if (
      (master.sourceApp === 'SMS_DLT' || master.sourceApp === 'Notif_Log') &&
      incoming.sourceApp !== 'SMS_DLT' &&
      incoming.sourceApp !== 'Notif_Log'
    ) {
      master.sourceApp = incoming.sourceApp;
      // Also upgrade provenance if incoming has exact page/table offset
      if (incoming.provenance.pageNumber) {
        master.provenance = incoming.provenance;
      }
    }
  }
}
